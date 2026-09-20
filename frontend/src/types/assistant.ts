export interface AssistantQueryRequest {
  query: string;
}

export interface AssistantQueryResponse {
  answer: string;
  sources: string[];
  access_denied: boolean;
}