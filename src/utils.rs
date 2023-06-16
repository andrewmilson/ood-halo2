use halo2_base::gates::flex_gate::FlexGateConfig;
use halo2_base::gates::GateInstructions;
use halo2_base::AssignedValue;
use halo2_base::Context;
use halo2_base::QuantumCell;
use halo2_proofs::halo2curves::FieldExt;
use num_traits::Pow;
use std::cell::RefCell;
use std::ops::Add;
use std::ops::Div;
use std::ops::Mul;
use std::ops::Neg;

#[derive(Clone)]
enum HybridValue<'a, F: FieldExt> {
    Value(AssignedValue<F>),
    Cell(QuantumCell<'a, F>),
}

/// Wrapper that implements rust ops on top of QuantumCell
// TODO: merge this type with QuantumCell
#[derive(Clone)]
pub struct HybridCell<'a, 'b, 'c, 'd, 'e, F: FieldExt> {
    chip: &'a FlexGateConfig<F>,
    ctx: &'b RefCell<&'c mut Context<'d, F>>,
    value: HybridValue<'e, F>,
}

impl<'a, 'b, 'c, 'd, 'e, F: FieldExt> HybridCell<'a, 'b, 'c, 'd, 'e, F> {
    pub fn from_val(
        chip: &'a FlexGateConfig<F>,
        ctx: &'b RefCell<&'c mut Context<'d, F>>,
        value: AssignedValue<F>,
    ) -> Self {
        let value = HybridValue::Value(value);
        HybridCell { chip, ctx, value }
    }

    pub fn from_constant(
        chip: &'a FlexGateConfig<F>,
        ctx: &'b RefCell<&'c mut Context<'d, F>>,
        value: F,
    ) -> Self {
        let value = HybridValue::Cell(QuantumCell::Constant(value));
        HybridCell { chip, ctx, value }
    }

    pub fn from_ref(
        chip: &'a FlexGateConfig<F>,
        ctx: &'b RefCell<&'c mut Context<'d, F>>,
        value: &'e AssignedValue<F>,
    ) -> Self {
        let value = HybridValue::Cell(QuantumCell::Existing(value));
        HybridCell { chip, ctx, value }
    }

    pub fn cell(&self) -> QuantumCell<'_, F> {
        match &self.value {
            HybridValue::Value(v) => QuantumCell::Existing(&v),
            HybridValue::Cell(c) => c.clone(),
        }
    }

    pub fn value(&self) -> Option<AssignedValue<F>> {
        use HybridValue::*;
        match &self.value {
            Value(v) => Some(v.clone()),
            Cell(QuantumCell::Existing(v)) => Some(AssignedValue::clone(v)),
            _ => None,
        }
    }
}

impl<'a, 'b, 'c, 'd, 'e, F: FieldExt> Add for HybridCell<'a, 'b, 'c, 'd, 'e, F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut ctx = self.ctx.borrow_mut();
        let value = self.chip.add(&mut ctx, &self.cell(), &rhs.cell()).unwrap();
        HybridCell::from_val(self.chip, &self.ctx, value)
    }
}

impl<'a, 'b, 'c, 'd, 'e, F: FieldExt> Neg for HybridCell<'a, 'b, 'c, 'd, 'e, F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut ctx = self.ctx.borrow_mut();
        let res = self.chip.neg(&mut ctx, &self.cell()).unwrap();
        HybridCell::from_val(self.chip, &self.ctx, res)
    }
}

impl<'a, 'b, 'c, 'd, 'e, F: FieldExt> Mul for HybridCell<'a, 'b, 'c, 'd, 'e, F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut ctx = self.ctx.borrow_mut();
        let res = self.chip.mul(&mut ctx, &self.cell(), &rhs.cell()).unwrap();
        HybridCell::from_val(self.chip, &self.ctx, res)
    }
}

impl<'a, 'b, 'c, 'd, 'e, F: FieldExt> Div for HybridCell<'a, 'b, 'c, 'd, 'e, F> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        let mut ctx = self.ctx.borrow_mut();
        let inv = self.chip.invert(&mut ctx, &rhs.cell()).unwrap();
        let inv_cell = QuantumCell::Existing(&inv);
        let res = self.chip.mul(&mut ctx, &self.cell(), &inv_cell).unwrap();
        HybridCell::from_val(self.chip, &self.ctx, res)
    }
}

impl<'a, 'b, 'c, 'd, 'e, F: FieldExt> Pow<usize> for HybridCell<'a, 'b, 'c, 'd, 'e, F> {
    type Output = Self;

    fn pow(self, rhs: usize) -> Self::Output {
        let mut ctx = self.ctx.borrow_mut();
        let res = self.chip.pow(&mut ctx, &self.cell(), rhs).unwrap();
        HybridCell::from_val(self.chip, &self.ctx, res)
    }
}
