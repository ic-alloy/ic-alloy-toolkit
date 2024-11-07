export const idlFactory = ({ IDL }) => {
  const Result = IDL.Variant({ 'Ok' : IDL.Text, 'Err' : IDL.Text });
  const Result_3 = IDL.Variant({ 'Ok' : IDL.Vec(IDL.Text), 'Err' : IDL.Text });
  const Result_2 = IDL.Variant({ 'Ok' : IDL.Bool, 'Err' : IDL.Text });
  const Result_4 = IDL.Variant({ 'Ok' : IDL.Nat64, 'Err' : IDL.Text });
  return IDL.Service({
    'get_address' : IDL.Func([], [Result], []),
    'get_balance' : IDL.Func([IDL.Opt(IDL.Text)], [Result], []),
    'get_balance_usdc' : IDL.Func([IDL.Opt(IDL.Text)], [Result], []),
    'get_batch_balances' : IDL.Func([IDL.Vec(IDL.Text)], [Result], []),
    'get_latest_block' : IDL.Func([], [Result], []),
    'send_eth' : IDL.Func([], [Result], []),
    'send_eth_with_fillers' : IDL.Func([], [Result], []),
    'sign_message' : IDL.Func([IDL.Text], [Result], []),
    'transfer_usdc' : IDL.Func([], [Result], []),
    'watch_blocks_get' : IDL.Func([], [Result_3], ['query']),
    'watch_blocks_is_polling' : IDL.Func([], [Result_2], ['query']),
    'watch_blocks_poll_count' : IDL.Func([], [Result_4], ['query']),
    'watch_blocks_start' : IDL.Func([], [Result], []),
    'watch_blocks_stop' : IDL.Func([], [Result], []),
    'watch_contract_event' : IDL.Func([], [Result], []),
    'watch_usdc_transfer_get' : IDL.Func([], [Result_3], ['query']),
    'watch_usdc_transfer_is_polling' : IDL.Func([], [Result_2], ['query']),
    'watch_usdc_transfer_poll_count' : IDL.Func([], [Result_4], ['query']),
    'watch_usdc_transfer_start' : IDL.Func([], [Result], []),
    'watch_usdc_transfer_stop' : IDL.Func([], [Result], []),
  });
};
export const init = ({ IDL }) => { return []; };
