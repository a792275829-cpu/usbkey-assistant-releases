import { AsyncLocalStorage } from "node:async_hooks";

const context = new AsyncLocalStorage();
export const withNativeAuthToken = (token, operation) => context.run(token, operation);
export const nativeAuthToken = () => context.getStore();
