use halo2_base::AssignedValue;
use halo2_proofs::halo2curves::FieldExt;
use sha2::Digest;
use sha2::Sha256;
use std::hash::Hash;
use std::iter::{Product, Sum};
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
    hash::Hasher,
    rc::Rc,
};

#[derive(Clone, Debug)]
pub enum AlgebraicExpression<F: FieldExt> {
    X,
    Constant(F),
    Challenge(usize),
    Hint(usize),
    Trace(/* =column */ usize, /* =offset */ isize),
    Add(
        Rc<RefCell<AlgebraicExpression<F>>>,
        Rc<RefCell<AlgebraicExpression<F>>>,
    ),
    Neg(Rc<RefCell<AlgebraicExpression<F>>>),
    Mul(
        Rc<RefCell<AlgebraicExpression<F>>>,
        Rc<RefCell<AlgebraicExpression<F>>>,
    ),
    Exp(Rc<RefCell<AlgebraicExpression<F>>>, isize),
    AssignedValue(AssignedValue<F>),
}

impl<F: FieldExt> AlgebraicExpression<F> {
    pub fn pow(&self, exp: usize) -> Self {
        Self::Exp(Rc::new(RefCell::new(self.clone())), exp.try_into().unwrap())
    }

    /// Calculates an upper bound on the degree in X.
    /// Output is of the form `(numerator_degree, denominator_degree)`
    pub fn degree(&self, trace_degree: usize) -> (usize, usize) {
        self.degree_impl(1, trace_degree)
    }

    // Copied from https://github.com/0xProject/OpenZKP
    fn degree_impl(&self, x_degree: usize, trace_degree: usize) -> (usize, usize) {
        use AlgebraicExpression::*;
        match self {
            X => (x_degree, 0),
            Hint(_) | Challenge(_) | Constant(_) | AssignedValue(_) => (0, 0),
            Trace(..) => (trace_degree, 0),
            Add(a, b) => {
                let (a_numerator, a_denominator) = a.borrow().degree_impl(x_degree, trace_degree);
                let (b_numerator, b_denominator) = b.borrow().degree_impl(x_degree, trace_degree);
                (
                    core::cmp::max(a_numerator + b_denominator, b_numerator + a_denominator),
                    a_denominator + b_denominator,
                )
            }
            Neg(a) => a.borrow().degree_impl(x_degree, trace_degree),
            Mul(a, b) => {
                let (an, ad) = a.borrow().degree_impl(x_degree, trace_degree);
                let (bn, bd) = b.borrow().degree_impl(x_degree, trace_degree);
                (an + bn, ad + bd)
            }
            Exp(a, e) => {
                let (n, d) = a.borrow().degree_impl(x_degree, trace_degree);
                if *e >= 0 {
                    (*e as usize * n, *e as usize * d)
                } else {
                    (isize::abs(*e) as usize * d, isize::abs(*e) as usize * n)
                }
            }
        }
    }

    // Copied from https://github.com/0xProject/OpenZKP
    /// Applies a mapped bottom-up traversal.
    /// The function applies to each node after application to its descendants
    pub fn map(&self, f: &mut impl FnMut(Self) -> Self) -> Self {
        use AlgebraicExpression::*;
        // TODO: why can't the copiler do this as a param
        let result = match self {
            // Tree types are recursed first
            Add(a, b) => Add(
                Rc::new(RefCell::new(a.borrow().map(f))),
                Rc::new(RefCell::new(b.borrow().map(f))),
            ),
            Neg(a) => Neg(Rc::new(RefCell::new(a.borrow().map(f)))),
            Mul(a, b) => Mul(
                Rc::new(RefCell::new(a.borrow().map(f))),
                Rc::new(RefCell::new(b.borrow().map(f))),
            ),
            Exp(a, e) => Exp(Rc::new(RefCell::new(a.borrow().map(f))), *e),

            // Leaf types are mapped as is.
            other => other.clone(),
        };

        f(result)
    }

    // Copied from https://github.com/0xProject/OpenZKP
    /// Applies a bottom-up traversal.
    pub fn traverse(&self, f: &mut impl FnMut(&Self)) {
        use AlgebraicExpression::*;
        match self {
            // Tree types are recursed first
            Add(a, b) | Mul(a, b) => {
                a.borrow().traverse(f);
                b.borrow().traverse(f);
            }
            // Neg(a) | Inv(a) | Exp(a, _) => a.traverse(f),
            Neg(a) | Exp(a, _) => a.borrow().traverse(f),
            _ => {}
        }

        f(self)
    }

    /// Applies a bottom-up traversal.
    /// The closure is given mutable access to the nodes.
    pub fn traverse_mut(&mut self, f: &mut impl FnMut(&mut Self)) {
        use AlgebraicExpression::*;
        match self {
            // Tree types are recursed first
            Add(a, b) | Mul(a, b) => {
                a.borrow_mut().traverse_mut(f);
                b.borrow_mut().traverse_mut(f);
            }
            // Neg(a) | Inv(a) | Exp(a, _) => a.traverse(f),
            Neg(a) | Exp(a, _) => a.borrow_mut().traverse_mut(f),
            _ => {}
        }

        f(self)
    }

    // Adapted from https://github.com/0xProject/OpenZKP
    pub fn trace_arguments(&self) -> BTreeSet<(usize, isize)> {
        use AlgebraicExpression::*;
        let mut arguments = BTreeSet::new();
        self.traverse(&mut |node| {
            if let &Trace(i, j) = node {
                arguments.insert((i, j));
            }
        });
        arguments
    }

    // Copied from https://github.com/0xProject/OpenZKP
    pub fn eval(
        &self,
        x: &F,
        hint: &impl Fn(usize) -> F,
        challenge: &impl Fn(usize) -> F,
        trace: &impl Fn(usize, isize) -> F,
    ) -> F {
        use AlgebraicExpression::*;
        match self {
            X => *x,
            &AssignedValue(_) => panic!(),
            &Constant(c) => c,
            &Challenge(i) => challenge(i),
            &Hint(i) => hint(i),
            &Trace(i, j) => trace(i, j),
            Add(a, b) => {
                a.borrow().eval(x, hint, challenge, trace)
                    + b.borrow().eval(x, hint, challenge, trace)
            }
            Neg(a) => -a.borrow().eval(x, hint, challenge, trace),
            Mul(a, b) => {
                a.borrow().eval(x, hint, challenge, trace)
                    * b.borrow().eval(x, hint, challenge, trace)
            }
            Exp(a, e) => {
                let eval = a.borrow().eval(x, hint, challenge, trace).pow(&[
                    0,
                    0,
                    0,
                    e.unsigned_abs() as u64,
                ]);
                if *e >= 0 {
                    eval
                } else {
                    eval.invert().unwrap()
                }
            }
        }
    }

    // TODO: docs. Also hash? or signature?
    // TODO: Fq since bigger field but may use Fp
    pub fn evaluation_hash(&self, x: F) -> F {
        let x_bytes = x.to_repr().as_ref().to_vec();

        let hint = |i: usize| {
            let mut hasher = Sha256::new();
            hasher.update(&x_bytes);
            hasher.update("hint");
            hasher.update(i.to_ne_bytes());
            from_bytes(&hasher.finalize())
        };

        let challenge = |i: usize| {
            let mut hasher = Sha256::new();
            hasher.update(&x_bytes);
            hasher.update("challenge");
            hasher.update(i.to_ne_bytes());
            from_bytes(&hasher.finalize())
        };

        let trace = |column: usize, offset: isize| {
            let mut hasher = Sha256::new();
            hasher.update(&x_bytes);
            hasher.update("trace");
            hasher.update(column.to_ne_bytes());
            hasher.update(offset.to_ne_bytes());
            from_bytes(&hasher.finalize())
        };

        self.eval(&x, &hint, &challenge, &trace)
    }

    /// TODO: improve the explanation: reuses shared nodes. determines node
    /// equality probabilistically using a kind of evaluation hash
    /// Inspired by Thorkil Værge's "Reusing Shared Nodes" article:
    /// https://neptune.cash/learn/speed-up-stark-provers-with-multicircuits/
    pub fn reuse_shared_nodes(&self) -> Self {
        use AlgebraicExpression::*;
        // let mut rng = rand::thread_rng();
        // random evaluation point
        // let x = Fq::rand(&mut rng);
        // TODO: make random
        let x = F::from_u128(5342847892374102789754);

        // build graph in O(n)
        let mut visited = BTreeMap::new();
        let Constant(root_hash) = self.map(&mut |node| {
            let evaluation_hash = node.evaluation_hash(x);

            // can't use entry with `or_insert_with` with because `visited` is borrowed inside
            #[allow(clippy::map_entry)]
            if !visited.contains_key(&evaluation_hash) {
                visited.insert(evaluation_hash, match node {
                    // TODO: `Rc` keyword like `box` keyword would be cool
                    // Add(Rc Constant(a), Rc Constant(b)) => ...
                    Add(a, b) => if let (Constant(a), Constant(b)) = (&*a.borrow(), &*b.borrow()) {
                        let a = Rc::clone(visited.get(a).unwrap());
                        let b = Rc::clone(visited.get(b).unwrap());
                        Rc::new(RefCell::new(Add(a, b)))
                    } else {
                        unreachable!()
                    },

                    // TODO: consider replacing items in node map if there is a more optimal representation
                    Mul(a, b) => if let (Constant(a), Constant(b)) = (&*a.borrow(), &*b.borrow()) {
                        let a = Rc::clone(visited.get(a).unwrap());
                        let b = Rc::clone(visited.get(b).unwrap());
                        Rc::new(RefCell::new(Mul(a, b)))
                    } else {
                        unreachable!()
                    },

                    Exp(a, e) => if let Constant(a) = &*a.borrow() {
                        let a = Rc::clone(visited.get(a).unwrap());
                        Rc::new(RefCell::new(Exp(a, e)))
                    } else {
                        unreachable!()
                    },

                    Neg(a) => if let Constant(a) = &*a.borrow() {
                        let a = Rc::clone(visited.get(a).unwrap());
                        Rc::new(RefCell::new(Neg(a)))
                    } else {
                        unreachable!()
                    },

                    // Add leaf nodes to the tree
                    other => Rc::new(RefCell::new(other))
                });
            }

            Constant(evaluation_hash)
        }) else {
            unreachable!()
        };

        // TODO: better way of doing this? seems pretty convoluted
        // TODO: debug assertion to compare new evaluation point?
        visited
            .into_iter()
            .find_map(|(k, v)| (k == root_hash).then(|| Rc::try_unwrap(v).ok()))
            .flatten()
            .unwrap()
            .into_inner()
    }
}

impl<F: FieldExt> Display for AlgebraicExpression<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use AlgebraicExpression::*;
        match self {
            X => write!(f, "x"),
            Constant(c) => write!(f, "{c:?}"),
            Challenge(i) => write!(f, "challenge[{i}]"),
            Hint(i) => write!(f, "hint[{i}]"),
            Trace(i, j) => write!(f, "Trace({i}, {j})"),
            Add(a, b) => match &*b.borrow() {
                Neg(b) => write!(f, "({} - {})", a.borrow(), b.borrow()),
                other => write!(f, "({} + {})", a.borrow(), other),
            },
            Neg(a) => write!(f, "-{}", a.borrow()),
            Mul(a, b) => write!(f, "({} * {})", a.borrow(), b.borrow()),
            Exp(a, e) => write!(f, "{}^({})", a.borrow(), e),
            AssignedValue(v) => write!(f, "assigned_value[{v:?}]"),
        }
    }
}

impl<F: FieldExt> Hash for AlgebraicExpression<F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        use AlgebraicExpression::*;
        match self {
            X => {
                "x".hash(state);
            }
            AssignedValue(_) => {
                panic!()
            }
            Constant(c) => {
                c.to_repr().as_ref().hash(state);
            }
            Hint(i) => {
                "hint".hash(state);
                i.hash(state);
            }
            Challenge(i) => {
                "challenge".hash(state);
                i.hash(state);
            }
            Trace(i, j) => {
                "trace".hash(state);
                i.hash(state);
                j.hash(state);
            }
            Add(a, b) => {
                "add".hash(state);
                a.borrow().hash(state);
                b.borrow().hash(state);
            }
            Neg(a) => {
                "neg".hash(state);
                a.borrow().hash(state);
            }
            Mul(a, b) => {
                "mul".hash(state);
                a.borrow().hash(state);
                b.borrow().hash(state);
            }
            Exp(a, e) => {
                "exp".hash(state);
                a.borrow().hash(state);
                e.hash(state);
            }
        }
    }
}

impl<F: FieldExt> Sum<AlgebraicExpression<F>> for AlgebraicExpression<F> {
    fn sum<I: Iterator<Item = AlgebraicExpression<F>>>(mut iter: I) -> Self {
        use AlgebraicExpression::Constant;
        iter.next()
            .map_or(Constant(F::zero()), |expr| iter.fold(expr, |a, b| a + b))
    }
}

impl<F: FieldExt> Product<AlgebraicExpression<F>> for AlgebraicExpression<F> {
    fn product<I: Iterator<Item = AlgebraicExpression<F>>>(mut iter: I) -> Self {
        // TODO: zero or one?
        use AlgebraicExpression::Constant;
        iter.next()
            .map_or(Constant(F::zero()), |expr| iter.fold(expr, |a, b| a * b))
    }
}

impl<F: FieldExt> Mul<&AlgebraicExpression<F>> for &AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    fn mul(self, rhs: &AlgebraicExpression<F>) -> Self::Output {
        Mul::mul(self.clone(), rhs.clone())
    }
}

impl<F: FieldExt> Mul<AlgebraicExpression<F>> for AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    fn mul(self, rhs: AlgebraicExpression<F>) -> AlgebraicExpression<F> {
        AlgebraicExpression::Mul(Rc::new(RefCell::new(self)), Rc::new(RefCell::new(rhs)))
    }
}

impl<F: FieldExt> Div<&AlgebraicExpression<F>> for &AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    fn div(self, rhs: &AlgebraicExpression<F>) -> Self::Output {
        Div::div(self.clone(), rhs.clone())
    }
}

impl<F: FieldExt> Div<AlgebraicExpression<F>> for AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: AlgebraicExpression<F>) -> AlgebraicExpression<F> {
        // self * AlgebraicExpression::Inv(Box::new(rhs))
        self * AlgebraicExpression::Exp(Rc::new(RefCell::new(rhs)), -1)
    }
}

impl<F: FieldExt> Add<&AlgebraicExpression<F>> for &AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    fn add(self, rhs: &AlgebraicExpression<F>) -> Self::Output {
        Add::add(self.clone(), rhs.clone())
    }
}

impl<F: FieldExt> Add<AlgebraicExpression<F>> for AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    fn add(self, rhs: AlgebraicExpression<F>) -> AlgebraicExpression<F> {
        AlgebraicExpression::Add(Rc::new(RefCell::new(self)), Rc::new(RefCell::new(rhs)))
    }
}

impl<F: FieldExt> Sub<&AlgebraicExpression<F>> for &AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    fn sub(self, rhs: &AlgebraicExpression<F>) -> Self::Output {
        Sub::sub(self.clone(), rhs.clone())
    }
}

impl<F: FieldExt> Sub<AlgebraicExpression<F>> for AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: AlgebraicExpression<F>) -> AlgebraicExpression<F> {
        self + rhs.neg()
    }
}

impl<F: FieldExt> Neg for AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    fn neg(self) -> Self::Output {
        AlgebraicExpression::Neg(Rc::new(RefCell::new(self)))
    }
}

impl<F: FieldExt> Neg for &AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    #[inline]
    fn neg(self) -> Self::Output {
        self.clone().neg()
    }
}

impl<F: FieldExt> Mul<F> for AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    fn mul(self, rhs: F) -> Self::Output {
        self * AlgebraicExpression::Constant(rhs)
    }
}

impl<F: FieldExt> Mul<&F> for &AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    fn mul(self, rhs: &F) -> Self::Output {
        self.clone() * AlgebraicExpression::Constant(*rhs)
    }
}

impl<F: FieldExt> Div<F> for AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: F) -> Self::Output {
        self * AlgebraicExpression::Constant(rhs.invert().unwrap())
    }
}

impl<F: FieldExt> Div<&F> for &AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: &F) -> Self::Output {
        self.clone() * AlgebraicExpression::Constant(rhs.invert().unwrap())
    }
}

impl<F: FieldExt> Add<F> for AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    fn add(self, rhs: F) -> Self::Output {
        self + AlgebraicExpression::Constant(rhs)
    }
}

impl<F: FieldExt> Add<&F> for &AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    fn add(self, rhs: &F) -> Self::Output {
        self.clone() + AlgebraicExpression::Constant(*rhs)
    }
}

impl<F: FieldExt> Sub<F> for AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    fn sub(self, rhs: F) -> Self::Output {
        self + AlgebraicExpression::Constant(-rhs)
    }
}

impl<F: FieldExt> Sub<&F> for &AlgebraicExpression<F> {
    type Output = AlgebraicExpression<F>;

    fn sub(self, rhs: &F) -> Self::Output {
        self.clone() + AlgebraicExpression::Constant(-*rhs)
    }
}

forward_ref_binop!(impl< F: FieldExt > Mul, mul for AlgebraicExpression<F>, AlgebraicExpression<F>);
forward_ref_binop!(impl< F: FieldExt > Div, div for AlgebraicExpression<F>, AlgebraicExpression<F>);
forward_ref_binop!(impl< F: FieldExt > Add, add for AlgebraicExpression<F>, AlgebraicExpression<F>);
forward_ref_binop!(impl< F: FieldExt > Sub, sub for AlgebraicExpression<F>, AlgebraicExpression<F>);
forward_ref_binop!(impl< F: FieldExt > Mul, mul for AlgebraicExpression<F>, F);
forward_ref_binop!(impl< F: FieldExt > Div, div for AlgebraicExpression<F>, F);
forward_ref_binop!(impl< F: FieldExt > Add, add for AlgebraicExpression<F>, F);
forward_ref_binop!(impl< F: FieldExt > Sub, sub for AlgebraicExpression<F>, F);

impl<F: FieldExt> MulAssign<AlgebraicExpression<F>> for AlgebraicExpression<F> {
    fn mul_assign(&mut self, other: AlgebraicExpression<F>) {
        *self = &*self * other
    }
}

impl<F: FieldExt> MulAssign<F> for AlgebraicExpression<F> {
    fn mul_assign(&mut self, rhs: F) {
        *self = &*self * rhs
    }
}

impl<F: FieldExt> DivAssign<AlgebraicExpression<F>> for AlgebraicExpression<F> {
    fn div_assign(&mut self, other: AlgebraicExpression<F>) {
        *self = &*self / other
    }
}

impl<F: FieldExt> DivAssign<F> for AlgebraicExpression<F> {
    fn div_assign(&mut self, rhs: F) {
        *self = &*self / rhs
    }
}

impl<F: FieldExt> AddAssign<AlgebraicExpression<F>> for AlgebraicExpression<F> {
    fn add_assign(&mut self, other: AlgebraicExpression<F>) {
        *self = &*self + other
    }
}

impl<F: FieldExt> AddAssign<F> for AlgebraicExpression<F> {
    fn add_assign(&mut self, rhs: F) {
        *self = &*self + rhs
    }
}

impl<F: FieldExt> SubAssign<AlgebraicExpression<F>> for AlgebraicExpression<F> {
    fn sub_assign(&mut self, other: AlgebraicExpression<F>) {
        *self = &*self - other
    }
}

impl<F: FieldExt> SubAssign<F> for AlgebraicExpression<F> {
    fn sub_assign(&mut self, rhs: F) {
        *self = &*self - rhs
    }
}

forward_ref_op_assign!(impl< F: FieldExt > MulAssign, mul_assign for AlgebraicExpression<F>, AlgebraicExpression<F>);
forward_ref_op_assign!(impl< F: FieldExt > DivAssign, div_assign for AlgebraicExpression<F>, AlgebraicExpression<F>);
forward_ref_op_assign!(impl< F: FieldExt > AddAssign, add_assign for AlgebraicExpression<F>, AlgebraicExpression<F>);
forward_ref_op_assign!(impl< F: FieldExt > SubAssign, sub_assign for AlgebraicExpression<F>, AlgebraicExpression<F>);
forward_ref_op_assign!(impl< F: FieldExt > MulAssign, mul_assign for AlgebraicExpression<F>, F);
forward_ref_op_assign!(impl< F: FieldExt > DivAssign, div_assign for AlgebraicExpression<F>, F);
forward_ref_op_assign!(impl< F: FieldExt > AddAssign, add_assign for AlgebraicExpression<F>, F);
forward_ref_op_assign!(impl< F: FieldExt > SubAssign, sub_assign for AlgebraicExpression<F>, F);

fn from_bytes<F: FieldExt>(bytes: &[u8]) -> F {
    let mut acc = F::one();
    for byte in bytes {
        acc += F::from_u128(*byte as u128);
        acc *= F::from_u128(256u128);
    }
    acc
}
