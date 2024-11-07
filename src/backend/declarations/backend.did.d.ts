import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export type Result = { 'Ok' : string } |
  { 'Err' : string };
export type Result_2 = { 'Ok' : boolean } |
  { 'Err' : string };
export type Result_3 = { 'Ok' : Array<string> } |
  { 'Err' : string };
export type Result_4 = { 'Ok' : bigint } |
  { 'Err' : string };
export interface _SERVICE {
  'get_address' : ActorMethod<[], Result>,
  'get_balance' : ActorMethod<[[] | [string]], Result>,
  'get_balance_usdc' : ActorMethod<[[] | [string]], Result>,
  'get_batch_balances' : ActorMethod<[Array<string>], Result>,
  'get_latest_block' : ActorMethod<[], Result>,
  'send_eth' : ActorMethod<[], Result>,
  'send_eth_with_fillers' : ActorMethod<[], Result>,
  'sign_message' : ActorMethod<[string], Result>,
  'transfer_usdc' : ActorMethod<[], Result>,
  'watch_blocks_get' : ActorMethod<[], Result_3>,
  'watch_blocks_is_polling' : ActorMethod<[], Result_2>,
  'watch_blocks_poll_count' : ActorMethod<[], Result_4>,
  'watch_blocks_start' : ActorMethod<[], Result>,
  'watch_blocks_stop' : ActorMethod<[], Result>,
  'watch_contract_event' : ActorMethod<[], Result>,
  'watch_usdc_transfer_get' : ActorMethod<[], Result_3>,
  'watch_usdc_transfer_is_polling' : ActorMethod<[], Result_2>,
  'watch_usdc_transfer_poll_count' : ActorMethod<[], Result_4>,
  'watch_usdc_transfer_start' : ActorMethod<[], Result>,
  'watch_usdc_transfer_stop' : ActorMethod<[], Result>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
