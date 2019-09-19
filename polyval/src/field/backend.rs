//! Field arithmetic backends



/// Field arithmetic backend
pub trait Backend:
    Copy + Add<Output = Self> + Mul<Output = Self> + From<Block> + Into<Block>
{
}
