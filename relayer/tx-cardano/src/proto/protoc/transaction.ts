/**
 * Generated by the protoc-gen-ts.  DO NOT EDIT!
 * compiler version: 3.6.1
 * source: transaction.proto
 * git: https://github.com/thesayyn/protoc-gen-ts */
import * as dependency_1 from "./google/protobuf/empty";
import * as pb_1 from "google-protobuf";
import * as grpc_1 from "@grpc/grpc-js";
export namespace tx {
    export class SignAndSubmitTxRequest extends pb_1.Message {
        #one_of_decls: number[][] = [];
        constructor(data?: any[] | {
            chain_id?: string;
            transaction_hex_string?: Uint8Array;
        }) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("chain_id" in data && data.chain_id != undefined) {
                    this.chain_id = data.chain_id;
                }
                if ("transaction_hex_string" in data && data.transaction_hex_string != undefined) {
                    this.transaction_hex_string = data.transaction_hex_string;
                }
            }
        }
        get chain_id() {
            return pb_1.Message.getFieldWithDefault(this, 1, "") as string;
        }
        set chain_id(value: string) {
            pb_1.Message.setField(this, 1, value);
        }
        get transaction_hex_string() {
            return pb_1.Message.getFieldWithDefault(this, 2, new Uint8Array(0)) as Uint8Array;
        }
        set transaction_hex_string(value: Uint8Array) {
            pb_1.Message.setField(this, 2, value);
        }
        static fromObject(data: {
            chain_id?: string;
            transaction_hex_string?: Uint8Array;
        }): SignAndSubmitTxRequest {
            const message = new SignAndSubmitTxRequest({});
            if (data.chain_id != null) {
                message.chain_id = data.chain_id;
            }
            if (data.transaction_hex_string != null) {
                message.transaction_hex_string = data.transaction_hex_string;
            }
            return message;
        }
        toObject() {
            const data: {
                chain_id?: string;
                transaction_hex_string?: Uint8Array;
            } = {};
            if (this.chain_id != null) {
                data.chain_id = this.chain_id;
            }
            if (this.transaction_hex_string != null) {
                data.transaction_hex_string = this.transaction_hex_string;
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            if (this.chain_id.length)
                writer.writeString(1, this.chain_id);
            if (this.transaction_hex_string.length)
                writer.writeBytes(2, this.transaction_hex_string);
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): SignAndSubmitTxRequest {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new SignAndSubmitTxRequest();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        message.chain_id = reader.readString();
                        break;
                    case 2:
                        message.transaction_hex_string = reader.readBytes();
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): SignAndSubmitTxRequest {
            return SignAndSubmitTxRequest.deserialize(bytes);
        }
    }
    export class SignAndSubmitTxResponse extends pb_1.Message {
        #one_of_decls: number[][] = [];
        constructor(data?: any[] | {
            transaction_id?: string;
        }) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("transaction_id" in data && data.transaction_id != undefined) {
                    this.transaction_id = data.transaction_id;
                }
            }
        }
        get transaction_id() {
            return pb_1.Message.getFieldWithDefault(this, 1, "") as string;
        }
        set transaction_id(value: string) {
            pb_1.Message.setField(this, 1, value);
        }
        static fromObject(data: {
            transaction_id?: string;
        }): SignAndSubmitTxResponse {
            const message = new SignAndSubmitTxResponse({});
            if (data.transaction_id != null) {
                message.transaction_id = data.transaction_id;
            }
            return message;
        }
        toObject() {
            const data: {
                transaction_id?: string;
            } = {};
            if (this.transaction_id != null) {
                data.transaction_id = this.transaction_id;
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            if (this.transaction_id.length)
                writer.writeString(1, this.transaction_id);
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): SignAndSubmitTxResponse {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new SignAndSubmitTxResponse();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        message.transaction_id = reader.readString();
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): SignAndSubmitTxResponse {
            return SignAndSubmitTxResponse.deserialize(bytes);
        }
    }
    interface GrpcUnaryServiceInterface<P, R> {
        (message: P, metadata: grpc_1.Metadata, options: grpc_1.CallOptions, callback: grpc_1.requestCallback<R>): grpc_1.ClientUnaryCall;
        (message: P, metadata: grpc_1.Metadata, callback: grpc_1.requestCallback<R>): grpc_1.ClientUnaryCall;
        (message: P, options: grpc_1.CallOptions, callback: grpc_1.requestCallback<R>): grpc_1.ClientUnaryCall;
        (message: P, callback: grpc_1.requestCallback<R>): grpc_1.ClientUnaryCall;
    }
    interface GrpcStreamServiceInterface<P, R> {
        (message: P, metadata: grpc_1.Metadata, options?: grpc_1.CallOptions): grpc_1.ClientReadableStream<R>;
        (message: P, options?: grpc_1.CallOptions): grpc_1.ClientReadableStream<R>;
    }
    interface GrpWritableServiceInterface<P, R> {
        (metadata: grpc_1.Metadata, options: grpc_1.CallOptions, callback: grpc_1.requestCallback<R>): grpc_1.ClientWritableStream<P>;
        (metadata: grpc_1.Metadata, callback: grpc_1.requestCallback<R>): grpc_1.ClientWritableStream<P>;
        (options: grpc_1.CallOptions, callback: grpc_1.requestCallback<R>): grpc_1.ClientWritableStream<P>;
        (callback: grpc_1.requestCallback<R>): grpc_1.ClientWritableStream<P>;
    }
    interface GrpcChunkServiceInterface<P, R> {
        (metadata: grpc_1.Metadata, options?: grpc_1.CallOptions): grpc_1.ClientDuplexStream<P, R>;
        (options?: grpc_1.CallOptions): grpc_1.ClientDuplexStream<P, R>;
    }
    interface GrpcPromiseServiceInterface<P, R> {
        (message: P, metadata: grpc_1.Metadata, options?: grpc_1.CallOptions): Promise<R>;
        (message: P, options?: grpc_1.CallOptions): Promise<R>;
    }
    export abstract class UnimplementedTransactionServiceService {
        static definition = {
            SignAndSubmitTx: {
                path: "/tx.TransactionService/SignAndSubmitTx",
                requestStream: false,
                responseStream: false,
                requestSerialize: (message: SignAndSubmitTxRequest) => Buffer.from(message.serialize()),
                requestDeserialize: (bytes: Buffer) => SignAndSubmitTxRequest.deserialize(new Uint8Array(bytes)),
                responseSerialize: (message: SignAndSubmitTxResponse) => Buffer.from(message.serialize()),
                responseDeserialize: (bytes: Buffer) => SignAndSubmitTxResponse.deserialize(new Uint8Array(bytes))
            }
        };
        [method: string]: grpc_1.UntypedHandleCall;
        abstract SignAndSubmitTx(call: grpc_1.ServerUnaryCall<SignAndSubmitTxRequest, SignAndSubmitTxResponse>, callback: grpc_1.sendUnaryData<SignAndSubmitTxResponse>): void;
    }
    export class TransactionServiceClient extends grpc_1.makeGenericClientConstructor(UnimplementedTransactionServiceService.definition, "TransactionService", {}) {
        constructor(address: string, credentials: grpc_1.ChannelCredentials, options?: Partial<grpc_1.ChannelOptions>) {
            super(address, credentials, options);
        }
        SignAndSubmitTx: GrpcUnaryServiceInterface<SignAndSubmitTxRequest, SignAndSubmitTxResponse> = (message: SignAndSubmitTxRequest, metadata: grpc_1.Metadata | grpc_1.CallOptions | grpc_1.requestCallback<SignAndSubmitTxResponse>, options?: grpc_1.CallOptions | grpc_1.requestCallback<SignAndSubmitTxResponse>, callback?: grpc_1.requestCallback<SignAndSubmitTxResponse>): grpc_1.ClientUnaryCall => {
            return super.SignAndSubmitTx(message, metadata, options, callback);
        };
    }
}