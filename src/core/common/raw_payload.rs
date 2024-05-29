use std::marker::PhantomData;

pub struct RawPayload<Version, Purpose> {
    version: PhantomData<Version>,
    purpose: PhantomData<Purpose>,
}





