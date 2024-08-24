export interface HttpRequest {
  getHeader(name: string): string | undefined;
}
