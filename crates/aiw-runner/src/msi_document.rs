use super::*;
use aiw_provider_wsb::{
    ImportedMsiDocumentTransferResult, ImportedMsiGuestRequest, ImportedMsiScenarioResult,
    MAX_INTERACTIVE_DOCUMENT_BYTES,
};

/// Verify the result and its separate document artifact before accepting evidence.
/// Receipt verification alone only binds each artifact to its own digest.
pub(crate) fn verify_output(
    output: &Path,
    request: &ImportedMsiGuestRequest,
    result: &ImportedMsiScenarioResult,
) -> Result<Option<ImportedMsiDocumentTransferResult>, RunnerError> {
    result
        .validate_for_request(request)
        .map_err(|error| RunnerError::Receipt(error.to_string()))?;
    let Some(transfer) = &result.document_transfer else {
        return Ok(None);
    };
    let bytes = read_bounded_bytes(
        &output.join("document-output.txt"),
        MAX_INTERACTIVE_DOCUMENT_BYTES,
    )?;
    verify_bytes(&bytes, transfer)?;
    Ok(Some(transfer.clone()))
}

pub(crate) fn verify_bytes(
    bytes: &[u8],
    transfer: &ImportedMsiDocumentTransferResult,
) -> Result<(), RunnerError> {
    transfer
        .validate()
        .map_err(|error| RunnerError::Receipt(error.to_string()))?;
    if bytes.len() as u64 > MAX_INTERACTIVE_DOCUMENT_BYTES
        || bytes.len() as u64 != transfer.output_size_bytes
        || hex::encode(Sha256::digest(bytes)) != transfer.output_sha256
        || std::str::from_utf8(bytes).is_err()
        || bytes.contains(&0)
    {
        return Err(RunnerError::Receipt(
            "interactive document output is not the receipt-bound bounded UTF-8 artifact".into(),
        ));
    }
    Ok(())
}
