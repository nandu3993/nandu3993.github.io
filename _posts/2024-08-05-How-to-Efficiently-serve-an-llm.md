---
title: How to Efficiently Serve an LLM?
date: 2024-08-05 +05:30
categories: [LLM, Inference, Optimization, Serving]
tags: [LLM, inference, optimization, serving]
author: tremo
---

## How to Efficiently Serve an LLM

LLMs, or **Large** Language Models, are named so because they can range from tens to hundreds of billions of parameters. Their utility is clear, as LLMs are setting new records on various benchmarks and now often match or exceed human performance in multiple tasks Consequently, many companies are eager to deploy them in production. However, due to the unprecedented size of LLMs, there are significant challenges in serving them, such as slow token generation (tokens/second), memory limits for loading model parameters, KV cache (explained later), compute limits, and more. In this article, we will cover several recent ideas to help set up a robust LLM serving system.
__LLM Serving Overview__

## LLM inference Steps

1. Multiple users send requests to the LLM Server through HTTPs/gRPC.
2. The LLM Server receives the requests and schedules them based on QoE definition.
   - **QoE (Quality of Experience)**: Defined by two metrics:
     - **TTFT (Time to First Token)**: The time it takes for a user to receive the first response token.
     - **TDS (Token Delivery Speed)**: The rate at which the user receives tokens, which should be uniform and above the reader’s reading speed for a positive user experience.
    
    
3. After scheduling, the LLM Inference process is divided into two phases:
   - **Prefill phase**: The LLM processes the input tokens in parallel and generates the output activations known as the “KV Cache”. This step is highly efficient at utilizing the GPU's parallel processing capabilities, making input tokens generally much cheaper than output tokens (as seen in the GPT-4o pricing chart). This phase produces the first output token and is typically compute-bound.
    
    
   - **Decode phase**: The LLM starts autoregressively generating output tokens one at a time. This phase is slower in terms of inference and is where optimizations are **necessary**. Output tokens at each step are concatenated with the previous tokens’ KV cache to generate the next token.
    

Many experts are innovating the inference stack, and multiple startups are competing to reduce costs to attract more customers.


Here are some interesting optimizations shared recently in research:

