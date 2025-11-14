---
title: "On the bruteforceability of time-based one-time passwords"
date: 2025-01-26
---

<script defer src="https://cdn.jsdelivr.net/npm/plotly.js-dist@2.21.0/plotly.min.js"></script>
<script defer src="https://cdnjs.cloudflare.com/ajax/libs/mathjax/2.7.1/MathJax.js?config=TeX-AMS-MML_HTMLorMML" type="text/javascript"></script>
<script defer src="https://cdnjs.cloudflare.com/ajax/libs/noUiSlider/15.8.1/nouislider.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/noUiSlider/15.8.1/nouislider.css"/>

<style>
#sliders {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
  width: 80%;
  margin: 20px auto;
}

.slider-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  width: 100%;
}

.slider-label {
  margin-bottom: 5px;
  font-size: 15px;
}

.noUi-target {
  width: 90%;
  margin: 0 auto;
}
</style>

It is hardly controversial to argue in 2025 that 6-digit time-based one-time passwords (TOTPs) are susceptible to brute-force attacks if not accompanied by appropriate rate-limiting countermeasures. When I recently found myself searching for a mathematical breakdown of this susceptibility, I was surprised to find that none seems to exist – only simplified descriptions that do not properly capture the subtleties of TOTPs. This lack of precision bugged me enough to do something about it.

What follows is my attempt to fill that gap. In this post, we'll look into the mathematics of TOTP brute-force attacks and develop an accurate description, skipping the shortcuts. Finally, we will take some time to discuss the importance of the various TOTP configuration parameters.

## Brief introduction to TOTPs
Before we dive into the math, let us first introduce TOTP and define some relevant terminology. If you've ever ~~been forced to enable~~ responsibly chosen to enable 2FA, you're probably already familiar with the principle of TOTPs from apps like Google Authenticator. The basic idea is simple: the 2FA app generates a new 6-digit code every 30 seconds (each *"time step"*) using the current time and a shared secret usually provided in a QR code during 2FA setup. To prove your identity, you (the *"prover"*) submit the code and the server (the *"validator"*) independently generates the same code and verifies that they match. Codes do not need to be remembered, they can't be used more than once, and all codes are equally likely to be generated. Lovely!

Since the current time is used in code generation, this scheme relies on the prover and validator staying reasonably time-synchronized. To account for potential clock drift and network latency, TOTP validators can choose to accept a number of the most recently expired codes (*"grace period codes"*) in addition to the correct code (the "*primary code"*). This optional grace period is intended to ensure that valid authentication attempts aren't unfairly rejected due to minor synchronization issues.

There are then three configuration options of interest to our brute-force analysis purposes: the number of OTP digits $$ D $$, the time step duration $$ L $$, and the number of grace period codes $$ \lambda $$. We can therefore describe a TOTP validator's configuration in completeness with the tuple $$ (D, L, \lambda) $$. 

Let us now take a look at these configuration parameters from an attacker's perspective. First of all, we can conclude that the OTP space has a relatively small size of $$ N = 10^D $$. At any given time, $$ 1 + \lambda $$ of these codes are acceptable to the validator, and during each time step, we can attempt a total of $$ n = v \cdot L $$ guesses, where $$ v $$ is our number of attempts per second.

## Brute-force mathematics
Other authors ([Luke Plant, 2019](https://lukeplant.me.uk/blog/posts/6-digit-otp-for-two-factor-auth-is-brute-forceable-in-3-days/) and [Michael Fincham, 2021](https://pulsesecurity.co.nz/articles/totp-bruting)) have previously used a binomial distribution to model the probability of a successful brute-force attack against TOTP validators. This is a close approximation, but it suffers from certain inaccuracies. In this section, I will attempt to derive a more exact description.

First of all, I will argue that a *hypergeometric* distribution constitutes a better starting point than a binomial distribution. To see why, let us consult the [Wikipedia article](https://en.wikipedia.org/wiki/Hypergeometric_distribution) on the subject:

> (...) the hypergeometric distribution is a discrete probability distribution that describes the probability of  $$ k $$ successes (random draws for which the object drawn has a specified feature) in $$ n $$ draws, __without__ replacement, from a finite population of size $$ N $$ that contains exactly $$ K $$ objects with that feature, wherein each draw is either a success or a failure. In contrast, the binomial distribution describes the probability of $$ k $$ successes in $$ n $$ draws __with__ replacement.

In this context, a *"random draw"* is a guess, the *"specified feature"* is the guess being a valid code, and *"replacement"* refers to whether or not we might submit the same guess multiple times. Clearly, any reasonable attacker would not repeat incorrect guesses within a single time step, as that would be guaranteed to fail. Let us therefore agree that the *without replacement* option makes more sense.

### The simplest case: $$ \lambda = 0 $$
Now we're ready to consider the simple case where $$ \lambda = 0 $$. Within each individual time step, we've agreed that the number of correct guesses $$ X $$ follows a hypergeometric distribution. Since there is no grace period and thus only one valid code, we set $$ K = 1 $$.

$$ X \sim Hypergeometric(N=10^D,\ K=1,\ n=vL) $$

Consequently, its [PMF](https://en.wikipedia.org/wiki/Probability_mass_function) is given by:

$$ Pr(X = k) = \frac{\binom{K}{k} \binom{N-K}{n-k}}{\binom{N}{n}} $$

Remember, we only need to guess correctly *once*; anything other than $$ X = 0 $$ correct guesses is considered a success. The probability of zero correct guesses (i.e. a *failure*) simplifies nicely:

$$ Pr(f) = Pr(X = 0) = \frac{\binom{K}{0} \binom{N-K}{n-0}}{\binom{N}{n}} = \frac{ \binom{N-K}{n}}{\binom{N}{n}} = \frac{ \binom{10^D - 1}{v L}}{\binom{10^D}{v L}} = \frac{10^D - v L}{10^D} $$

$$ Pr(f) $$ represents the probability of failure during a *single* time step. Now, what happens when our brute-force attack spans multiple time steps? The probability of overall failure $$ Pr(F) $$ is equivalent to the probability of failing every individual time step. As such, we can describe the probability of failure after a $$ T $$-second attack as the probability of failing $$ T / L $$ consecutive time steps.

$$ Pr(F) = {Pr(f)}^{T/L} $$

Conversely, the probability of overall success must then be:

$$ Pr(S) = 1 - Pr(F) $$

This is a complete description of the success probability in the simple case where $$ \lambda = 0 $$. As we'll see in the next section, the general case is a bit more convoluted.

### The general case
It is tempting to conclude that in the general case where $$ \lambda $$ can take on a non-zero value, we can adjust our model simply by setting $$ K = 1 + \lambda $$. Unfortunately, it's not quite that simple. 

Consider what happens once we enter a new time step during our attack: a new primary code is generated, the previous one becomes a grace period code, and the oldest grace period code expires. At this point, *any code* could be valid, but some codes are less probable than others. Specifically, our failed attempts from the previous time step might match the new primary code, but they will certainly not be accepted as grace period codes. For this reason, we should not repeat guesses from the last $$ \lambda $$ time steps, as they are less likely to result in a success. By applying this intuitive optimization strategy, we can slightly improve our chances of success.

So how do we express this improvement mathematically? Instead of considering $$ 1 + \lambda $$ codes to be valid simultaneously, we consider the probability of guessing each valid code individually. For each grace period code, we've effectively reduced the size of the OTP search space by $$ n = v L $$ guesses for each time step in which the code has been active. As such, we can express $$ Pr(f) $$ as a product of $$ \lambda + 1 $$ differently parameterized hypergeometric probabilities. We introduce $$ N_i = N - i v L $$ to denote the size of the reduced search space for a code that has been active for $$ i $$ time steps. 

$$
\begin{aligned}
Pr(f) &=  Pr(X = 0 ; N_0) \cdot Pr(X = 0 ; N_1) \cdots Pr(X = 0 ; N_{\lambda}) \\
      &= \prod_{i=0}^{\lambda}{Pr(X = 0 ; N_i)}
\end{aligned}
$$

Of course, this expression is only valid once the attack has been ongoing for at least $$ \lambda $$ time steps. Before that, we have not yet collected the necessary information by guessing incorrectly and we can therefore not reap the benefits of a reduced search space. For simplicity, we will ignore this *"slow start"* as its effect is negligible and needlessly notationally complicated.

As in the simple case, the probability of failure (and success) after $$ T $$ seconds can be expressed as:

$$ Pr(F) = {Pr(f)}^{T/L} $$

$$ Pr(S) = 1 - Pr(F) $$

At last! We have obtained an expression for the probability of a successful brute-force attack within $$ T $$ seconds with $$ v $$ attempts per second against a TOTP validator with configuration $$ (D, L, \lambda) $$.

## Let's see some results
Now that we have related the attack duration to the probability of success, let's see what kind of results we get when we plug in some parameter values. I've included an interactive graph below for you to play with the various parameters and see how they affect the time required for a probable compromise. 

<div id="plot"></div>
<div id="sliders">
<div class="slider-container">
    <div class="slider-label">\(v\) (attempts per second): <span id="v-label">1</span></div>
    <div id="v-slider"></div>
</div>
<div class="slider-container">
    <div class="slider-label">\(L\) (time step duration): <span id="L-label">30</span> seconds</div>
    <div id="L-slider"></div>
</div>
<div class="slider-container">
    <div class="slider-label">\(\lambda\) (grace period parameter): <span id="lambda-label">1</span></div>
    <div id="lambda-slider"></div>
</div>
<div class="slider-container">
    <div class="slider-label">\(D\) (number of digits): <span id="D-label">6</span></div>
    <div id="D-slider"></div>
</div>
</div>

<script>
let D = 6;
let v = 10;
let L = 30;
let lambda = 1;

function probByTime(T) {
    if (T == 0) return 0;

    let otpSpaceSize = 10 ** D;
    let vL = v * L;
    
    let result = 1;

    for (let i = 0; i <= lambda; i++) {
        let subtractable = i * vL;

        let Ni = otpSpaceSize - subtractable;

        if (Ni <= 0 || vL > Ni) {
            // if the entire space is covered, the probability of success is 100%
            return 1;
        }

        let subresult = 1 - (vL / Ni);

        result *= subresult;
    }

    return 1 - Math.pow(result, T / L);
}

function distribution() {
    const x = Array.from({length: 4*3*24+1}, (_, i) => i/4);
    const y = x.map(xVal => probByTime(60*60*xVal));
    return {x, y};
}

function updatePlot() {
    const data = distribution();
    const x = data.x;
    const y = data.y;

    const trace = {
        x: x,
        y: y,
        mode: 'lines',
        type: 'scatter'
    };

    const layout = {
        title: 'Brute-force success probability over time',
        xaxis: { title: 'Time (hours)', range: [0, 3*24+2] },
        yaxis: { title: 'Probability of success', range: [0, 1.1] }
    };

    Plotly.newPlot('plot', [trace], layout);
}

const vSlider = document.getElementById('v-slider');
const LSlider = document.getElementById('L-slider');
const lambdaSlider = document.getElementById('lambda-slider');
const DSlider = document.getElementById('D-slider');

function updateLabels() {
    document.getElementById('v-label').textContent = `${v}`;
    document.getElementById('L-label').textContent = `${L}`;
    document.getElementById('lambda-label').textContent = `${lambda}`;
    document.getElementById('D-label').textContent = `${D}`;
}

document.addEventListener("DOMContentLoaded", () => {
    noUiSlider.create(vSlider, {
        start: [10],
        range: { min: 1, max: 100 },
        step: 1
    });

    noUiSlider.create(LSlider, {
        start: [30],
        range: { min: 10, max: 15*60 },
        step: 5
    });

    noUiSlider.create(lambdaSlider, {
        start: [1],
        range: { min: 0, max: 8 },
        step: 1
    });

    noUiSlider.create(DSlider, {
        start: [6],
        range: { min: 4, max: 8 },
        step: 1
    });

    vSlider.noUiSlider.on('update', function(values) {
        v = Math.round(values[0]);
        updateLabels();
        updatePlot();
    });

    LSlider.noUiSlider.on('update', function(values) {
        L = Math.round(values[0]);
        updateLabels();
        updatePlot();
    });

    lambdaSlider.noUiSlider.on('update', function(values) {
        lambda = Math.round(values[0]);
        updateLabels();
        updatePlot();
    });

    DSlider.noUiSlider.on('update', function(values) {
        D = Math.round(values[0]);
        updateLabels();
        updatePlot();
    });

    updateLabels();
    updatePlot();
});

</script>

So what conclusions can we draw from this mathematical venture of ours? 

To my own personal dismay, the time step duration seems to carry very little weight. This unfortunately means that the simplified binomial model employed by other authors is almost indistinguishable from the one we developed in this article. In other words, our careful analysis turned out to be little more than computationally expensive pedantry. Well, at least now we know.

Unsurprisingly, the grace period parameter $$ \lambda $$ makes quite a significant difference to TOTP bruteforceability. It is my opinion that $$ \lambda $$ should generally be set to $$ 0 $$ in production systems, as it considerably weakens the security of TOTP authentication, and the synchronization issues it is supposed to address are presumably quite rare – unless the prover submits their code at the very last second, which I'd wager most users instinctively avoid anyway.

As we'd suspected, 6-digit TOTPs are indeed troublingly bruteforceable; a ~50% chance of success can be obtained in a matter of hours with even a modest request rate of 20-30 requests per second. And with specialized software like [Turbo Intruder](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack), much higher rates can often be achieved. 

Hopefully, these results are enough to convince any lingering skeptics that TOTP systems should always be accompanied by robust rate-limiting protections.

