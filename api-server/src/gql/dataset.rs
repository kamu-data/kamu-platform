use async_graphql::*;
use chrono::prelude::*;
use kamu::domain;

use super::*;

#[derive(SimpleObject, Debug, Clone)]
#[graphql(complex)]
pub(crate) struct Dataset {
    #[graphql(skip)]
    account_id: AccountID,

    /// Unique identifier of the dataset
    id: DatasetID,
}

#[ComplexObject]
impl Dataset {
    #[graphql(skip)]
    pub fn new(account_id: AccountID, id: DatasetID) -> Self {
        Self { account_id, id }
    }

    #[graphql(skip)]
    fn get_chain(&self, ctx: &Context<'_>) -> Result<Box<dyn domain::MetadataChain>> {
        let metadata_repo = from_catalog::<dyn domain::MetadataRepository>(ctx).unwrap();
        Ok(metadata_repo.get_metadata_chain(&self.id.as_local_ref())?)
    }

    /// Returns the user or organization that owns this dataset
    async fn owner(&self) -> Account {
        Account::User(User::new(self.account_id.clone()))
    }

    /// Symbolic name of the dataset.
    /// Name can change over the dataset's lifetime. For unique identifier use `id()`.
    async fn name(&self, ctx: &Context<'_>) -> Result<String> {
        let metadata_repo = from_catalog::<dyn domain::MetadataRepository>(ctx).unwrap();
        let hdl = metadata_repo.resolve_dataset_ref(&self.id.as_local_ref())?;
        Ok(hdl.name.into())
    }

    /// Returns the kind of a dataset (Root or Derivative)
    async fn kind(&self, ctx: &Context<'_>) -> Result<DatasetKind> {
        let metadata_repo = from_catalog::<dyn domain::MetadataRepository>(ctx).unwrap();
        let summary = metadata_repo.get_summary(&self.id.as_local_ref())?;
        Ok(summary.kind.into())
    }

    /// Access to the data of the dataset
    async fn data(&self) -> DatasetData {
        DatasetData::new(self.id.clone())
    }

    /// Access to the metadata of the dataset
    async fn metadata(&self) -> DatasetMetadata {
        DatasetMetadata::new(self.id.clone())
    }

    // TODO: Performance
    /// Creation time of the first metadata block in the chain
    async fn created_at(&self, ctx: &Context<'_>) -> Result<DateTime<Utc>> {
        let chain = self.get_chain(ctx)?;
        let first_block = chain
            .iter_blocks_ref(&domain::BlockRef::Head)
            .map(|(_, b)| b)
            .last()
            .expect("Dataset without blocks");
        Ok(first_block.system_time)
    }

    /// Creation time of the most recent metadata block in the chain
    async fn last_updated_at(&self, ctx: &Context<'_>) -> Result<DateTime<Utc>> {
        let chain = self.get_chain(ctx)?;
        let last_block = chain
            .iter_blocks_ref(&domain::BlockRef::Head)
            .map(|(_, b)| b)
            .next()
            .expect("Dataset without blocks");
        Ok(last_block.system_time)
    }
}
