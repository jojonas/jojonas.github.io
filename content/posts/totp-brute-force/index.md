---
title: 'TOTP Brute-Force Statistics'
date: 2026-03-09T21:10:00+01:00
draft: false
tags: ["Penetration Testing", "Mathematics", "Statistics"]
---

There is this tiny statistics problem in IT security that almost nobody talks
about, yet I have seen people get it wrong many times in the past: Calculation
of the success probability of brute-force attacks against TOTP two-factor
authenticators.

As a reminder: TOTP tokens are defined in {{< rfc 6238 >}}. They usually consist
of six-digit strings that change every 30 seconds. The entire sequence of tokens
is derived from a secret (and the current time) in a way that makes token
prediction without the secret impossible. TOTP tokens are commonly used as a
second factor, in addition to a user's password, reducing the impact of a
potential password compromise.

In various engagements I have seen TOTP validation implementations that do not
rate-limit the process of entering and validating the TOTP token. Due to the
limited search space (6 digits = "only" 1000000 possible tokens) this can render
the second factor ineffective and allow attackers to bypass 2FA. When
documenting that finding, it's usually a good idea to provide the client with
some numbers answering the question "How long does it take?". However, over the
years I have seen several colleagues calculate that number incorrectly, which
highlights how easy it is to overlook some of the statistical nuances involved.

### Naive Approach

The naive (and wrong) approach is as follows: Assuming 100 guesses per second
(rate _R_) and a search space of 1000000 possible tokens (6 digits, search space
_N_) the attack will be successful after:


```math
t = \frac{N}{R} = \frac{1000000\,\text{tokens}}{100\,\text{tokens}/\text{s}} = 10000\,\text{s} \approx 2\,\text{h}\:46\,\text{m}
```

Unfortunately, this calculation underestimates the fact that in reality the
window of opportunity (for an attacker) "jumps" every 30 seconds. That means,
there is usually[^1] a possibility that the attacker might _never_ guess the
correct code, even after billions of guesses - if the window always "jumps" away
from their next guess.

[^1]: As long as the attacker does not exhaust the _entire_ search space
    (1000000 guesses) within one window (30 seconds).

### Better Calculation

A much better approximation can be made by looking at each window individually.
For each window of length _T_, the probability of brute-forcing (i.e. guessing
without replacement) the correct code is:

```math
P(\text{correct guess}, T) = \frac{R \cdot T}{N}
```

In order to calculate the probability that the correct code is found after _n_
windows, we need to take a short detour via the probability that the correct
code is _not_ found:

```math
P(\text{at least one correct guess after $n$ windows}) = 1 - \left(1 - P(\text{correct guess})\right)^n =  1 - \left(1 - \frac{R \cdot T}{N} \right) ^ n
```

Finally, instead of looking at _n_ windows, let's plug in a time _t_ and the
window time _T_. This yields our final[^2] result:

[^2]: The exact result would be a combination of a step function with linear
    interpolation. The "final result" shown in this post is only an
    approximation. I originally wanted to include the full derivation, but this
    would have made the post even more boring.

```math
P(\text{at least one correct guess after $t$}) = 1 - \left(1 - \frac{R \cdot T}{N} \right) ^ \frac{t}{T}
```

The following plot shows this function with the parameters _R = 100/s_, _T=30s_,
_N=1000000_. As expected, the probability approaches 100%, but never quite
reaches it.

```chartjs
{
  "type": "line",
  "data": {
    "labels": [0.0, 15.0, 30.0, 45.0, 60.0, 75.0, 90.0, 105.0, 120.0, 135.0, 150.0, 165.0, 180.0, 195.0, 210.0, 225.0, 240.0, 255.0, 270.0, 285.0, 300.0, 315.0, 330.0, 345.0, 360.0, 375.0, 390.0, 405.0, 420.0, 435.0, 450.0, 465.0, 480.0],
    "datasets": [
      {
        "label": "Success Probability",
        "data": 
[0.0, 8.62, 16.5, 23.69, 30.27, 36.28, 41.77, 46.79, 51.38, 55.57, 59.4, 62.9, 66.1, 69.02, 71.69, 74.13, 76.36, 78.4, 80.26, 81.96, 83.51, 84.94, 86.23, 87.42, 88.5, 89.5, 90.4, 91.23, 91.98, 92.68, 93.31, 93.88, 94.41],
        "pointStyle": false
      }
    ]
  },
  "options": {
    "scales": {
      "x": {
        "title": {
          "display": true,
          "text": "t [minutes]"
        }
      },
      "y": {
        "title": {
          "display": true,
          "text": "Probability [%]"
        }
      }
    }
  }
}
```


### Inversion

Often we would like to calculate at which time a desired probability _p_ has
been reached. We start by calculating the amount of windows that must pass:

```math
t = T \cdot \frac{\ln(1 - p)}{\ln\left(1-\frac{R \cdot T}{N} \right)}
```

Here we can find an approximation by applying the Taylor series of {{< math
>}}\ln(1-x)\:\text{if}\:x = \frac{R \cdot T}{N} \ll 1{{</ math>}} to the
divisor:

```math
f(x) = \ln(1 - x) = -x - \mathcal{O}(x^2)
```
<br>

```math
t = T \cdot \frac{- \ln(1 - p)}{\frac{R \cdot T}{N}} = - \ln(1 - p) \cdot \frac{N}{R}
```

In practice, we can almost always use this approximation. I verified that even
at _R = 1000/s_, the curves only differ by around 10 seconds at _p = 0.5_.

For the parameters shown in the plot above (_R = 100/s_, _T=30s_, _N=1000000_),
a 50% probability is reached after 115 minutes (1h 55min), a 90% probability after 384 minutes (6h 23min).

### Accepting Multiple Codes

The probability formula can be easily extended for cases where the last _m-1_
TOTP codes are also accepted (total accepted: _m_):

```math
P(t) = 1 - \left( 1 - \frac{m \cdot R \cdot T}{N} \right) ^ \frac{t}{T}
```

For the inversion, this results in:

```math
t = T \cdot \frac{\ln(1 - p)}{\ln\left(1-\frac{m \cdot R \cdot T}{1000000} \right)} \approx - \ln(1 - p) \cdot \frac{1000000}{m \cdot R}
```

One consequence is that by also accepting the last code, the brute-force time is
halved.

### Interactive Calculator

For all fellow penetration testers who need to document this (or a similar) issue, I've vibe coded a <a href="https://totp.app.jonaslieb.de" target="_blank">TOTP Brute-Force Calculator</a>!
