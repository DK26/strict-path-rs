# Unlocking the Mathematical Security of strict-path

> **Welcome!** You're about to learn how to make filesystem attacks *mathematically impossible* in your code. No CVE research required. No security expertise needed. Just types, the compiler, and some clever design patterns.

This tutorial builds your understanding step-by-step, from basic path validation to compile-time authorization guarantees. Each section introduces **one concept at a time**, with runnable examples you can copy and paste.

## What You'll Learn

**Chapter 1: [The Basic Promise](./chapter1_basic_promise.md)**  
Learn how `StrictPath` makes path escapes mathematically impossible, without any markers yet.

**Chapter 2: [The Mix-Up Problem](./chapter2_mixup_problem.md)**  
Discover the confusing problem that emerges when you have multiple boundaries.

**Chapter 3: [Markers to the Rescue](./chapter3_markers.md)**  
See how markers solve the mix-up problem with compile-time domain separation.

**Chapter 4: [Authorization with change_marker()](./chapter4_authorization.md)**  
Learn to encode authorization requirements in the type system using `change_marker()`.

**Chapter 5: [Virtual Paths](./chapter5_virtual_paths.md)**  
Understand how `VirtualPath` extends `StrictPath` with user-friendly sandboxing semantics.

**Chapter 6: [Feature Integration](./chapter6_features.md)**  
Integrate with your ecosystem using feature-gated constructors (`dirs`, `tempfile`, `app-path`, `serde`).

## The Progressive Guarantee

As you progress through the chapters, the compiler's guarantees grow stronger:

| Chapter | What You Master        | The Guarantee                        |
| ------- | ---------------------- | ------------------------------------ |
| **1**   | Basic boundaries       | Path cannot escape                   |
| **2**   | (Problem statement)    | —                                    |
| **3**   | Domain separation      | Path is in correct domain            |
| **4**   | Authorization encoding | Authorization proven by compiler     |
| **5**   | Virtual sandboxes      | Clean UX + safe system paths         |
| **6**   | Ecosystem integration  | External APIs + boundary enforcement |

## The End Result

> **By the end of this tutorial, you'll understand how the Rust compiler can mathematically prove that:**
> - ✅ Paths cannot escape their boundaries
> - ✅ Paths are in the correct resource domain
> - ✅ Authorization was granted for the specified operations
> - ✅ All of this happens at **compile time** — no runtime overhead!

Ready? Let's unlock the security vault. 🔐

**[Start with Chapter 1: The Basic Promise →](./chapter1_basic_promise.md)**
