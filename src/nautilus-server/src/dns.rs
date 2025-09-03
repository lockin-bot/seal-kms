use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};

// Custom handler that responds with 127.0.0.1 to any query
pub struct LocalhostHandler;

#[async_trait::async_trait]
impl RequestHandler for LocalhostHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response: R,
    ) -> ResponseInfo {
        let query = request.request_info().unwrap().query;
        let name = query.name().to_lowercase();
        println!("DNS Query: {}", &name.to_ascii());

        let record = Record::from_rdata(name, 600, RData::A(A::new(127, 0, 0, 1)));

        let result = response
            .send_response(MessageResponseBuilder::from_message_request(request).build(
                request.header().clone(),
                &[record],
                &[],
                &[],
                &[],
            ))
            .await;
        match result {
            Ok(info) => info,
            Err(e) => {
                eprintln!("Failed to send response: {}", e);
                ResponseInfo::from(request.header().clone())
            }
        }
    }
}
