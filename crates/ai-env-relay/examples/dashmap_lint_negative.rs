//! R-74's proof, for `make lint-negative` only (feature `lint-negative`): clippy must REJECT this file with exactly
//! one `holding a disallowed type across an await point` per dashmap entry of `clippy.toml`'s
//! `await-holding-invalid-types`, nine in all. Each function holds one guard type, bound directly (the lint misses
//! an `Option` of one, hence R-75), across one `.await`. It is never run.

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

async fn tick() {
    tokio::task::yield_now().await;
}

async fn hold_ref(m: &DashMap<u32, u32>) {
    if let Some(guard) = m.get(&1) {
        tick().await;
        drop(guard);
    }
}

async fn hold_ref_mut(m: &DashMap<u32, u32>) {
    if let Some(guard) = m.get_mut(&1) {
        tick().await;
        drop(guard);
    }
}

async fn hold_ref_multi(m: &DashMap<u32, u32>) {
    let first = {
        let mut it = m.iter();
        it.next()
    };
    if let Some(guard) = first {
        tick().await;
        drop(guard);
    }
}

async fn hold_ref_mut_multi(m: &DashMap<u32, u32>) {
    let first = {
        let mut it = m.iter_mut();
        it.next()
    };
    if let Some(guard) = first {
        tick().await;
        drop(guard);
    }
}

async fn hold_entry(m: &DashMap<u32, u32>) {
    let entry = m.entry(1);
    tick().await;
    drop(entry);
}

async fn hold_occupied(m: &DashMap<u32, u32>) {
    let occupied = match m.entry(1) {
        Entry::Occupied(o) => o,
        Entry::Vacant(_) => return,
    };
    tick().await;
    drop(occupied);
}

async fn hold_vacant(m: &DashMap<u32, u32>) {
    let vacant = match m.entry(2) {
        Entry::Vacant(v) => v,
        Entry::Occupied(_) => return,
    };
    tick().await;
    drop(vacant);
}

async fn hold_iter(m: &DashMap<u32, u32>) {
    let it = m.iter();
    tick().await;
    drop(it);
}

async fn hold_iter_mut(m: &DashMap<u32, u32>) {
    let it = m.iter_mut();
    tick().await;
    drop(it);
}

fn main() {
    let m = DashMap::new();
    m.insert(1, 1);
    let futures = (
        hold_ref(&m),
        hold_ref_mut(&m),
        hold_ref_multi(&m),
        hold_ref_mut_multi(&m),
        hold_entry(&m),
        hold_occupied(&m),
        hold_vacant(&m),
        hold_iter(&m),
        hold_iter_mut(&m),
    );
    drop(futures);
}
