# How to Use

With our pallet now compiling and passing it's tests, we're ready to add it to our node.

```
git clone -b v2.0.0-rc3 --depth 1 https://github.com/substrate-developer-hub/substrate-node-template
```

We first add our newly-created crate as a dependency in the node's runtime Cargo.toml. Then we tell the pallet to only build its std feature when the runtime itself does, as follows:

`my-node/runtime/Cargo.toml`

``` TOML
# --snip--

[dependencies.pallet-did]
default-features = false
git = 'https://github.com/substrate-developer-hub/pallet-did'
package = 'pallet-did'
tag = '2.0.0-rc3'
version = '2.0.0-rc3'


# toward the bottom
[features]
default = ['std']
std = [
    'pallet-did/std',
    # --snip--
]
```
Next we will update `my-node/runtime/src/lib.rs` to actually use our new runtime pallet, by adding a trait implementation with our pallet_did and add it in our construct_runtime! macro.

``` rust
// add this import at the top
use sp_runtime::MultiSigner;

// add the following code block
impl pallet_did::Trait for Runtime {
  type Event = Event;
  type Public = MultiSigner;
  type Signature = Signature;
}

// --snip--
construct_runtime!(
  pub enum Runtime where
    Block = Block,
    NodeBlock = opaque::Block,
    UncheckedExtrinsic = UncheckedExtrinsic
  {
    // --snip--
    // add the following line
    PalletDID: pallet_did::{Module, Call, Storage, Event<T>},
  }
);
```

Follow the [Creating an External Pallet](https://substrate.dev/docs/en/tutorials/creating-a-runtime-module) to get a more detailed explanation on how to integrate a pallet into your node.

## Building and Testing

Before you release your pallet, you should check that it can:

1. Build to Native:

    ```
    cargo build --release
    ```

2. Pass your tests:

    ```
    cargo test -p pallet-did
    ```
