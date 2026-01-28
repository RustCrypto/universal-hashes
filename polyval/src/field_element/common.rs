/// Compute the first `N` powers of `h`, in reverse order.
///
/// Implemented generically so it can be shared by software and SIMD implementations.
#[inline]
pub(super) fn powers_of_h<T, Mul, const N: usize>(h: T, mul: Mul) -> [T; N]
where
    T: Copy,
    Mul: Fn(T, T) -> T,
{
    let mut pow = [h; N];

    // TODO: improve pipelining by using more square operations?
    let mut prev = h;
    for (i, v) in pow.iter_mut().rev().enumerate() {
        *v = h;
        if i > 0 {
            *v = mul(*v, prev);
        }
        prev = *v;
    }
    pow
}
