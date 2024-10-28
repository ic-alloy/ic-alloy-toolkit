import { Link, createLazyFileRoute } from '@tanstack/react-router'

import { backend } from '../../backend/declarations'
import { useMutation, useQuery } from '@tanstack/react-query'
import Source from '../components/source'
import Spinner from '../components/spinner'

export const Route = createLazyFileRoute('/transfer_usdc')({
  component: Page,
})

function parseUsdcString(usdc?: string) {
  if (!usdc) return "0";
  return (Number.parseInt(usdc) / Math.pow(10, 6)).toString();
}

function Page() {
  const { data: accountBalanceResult, isFetching: isFetchingAccountBalance } =
    useQuery({
      queryKey: ['get_balance_usdc'],
      queryFn: () => backend.get_balance_usdc([]),
    })

  const accountBalance =
    accountBalanceResult && 'Ok' in accountBalanceResult
      ? accountBalanceResult.Ok
      : undefined

  const {
    data: txResult,
    isPending: isSendingTx,
    mutate: sendTx,
  } = useMutation({
    mutationFn: () => backend.transfer_usdc(),
  })

  return (
    <>
      <Link to="/">
        <button> Menu</button>
      </Link>
      <div className="card">
        <p>
          Transfer a small amount of USDC from the canister eth address back to the canister eth address.
        </p>
        <p>
          <i>
            If call fails due to lack of funds, top up the canister eth address
            with some Sepolia USDC.
          </i>
        </p>
        <p>
          <i>
            Instead of using Alloy fillers for nonce handling, the{' '}
            <code>transfer_usdc</code> function implements that manually instead to
            minimize the number of requests sent to the RPC.
          </i>
        </p>
        <p>
          <i>
            This canister call can take up to a minute to complete, please be
            patient.
          </i>
        </p>

        <p>
          Canister USDC balance:{' '}
          {isFetchingAccountBalance ? <Spinner /> : <b>{parseUsdcString(accountBalance)} USDC</b>}
        </p>
        <button disabled={isSendingTx} onClick={() => void sendTx()}>
          {isSendingTx ? <Spinner /> : 'transfer_usdc()'}
        </button>
        {txResult && <pre>{JSON.stringify(txResult, null, 2)}</pre>}
        <Source file="transfer_usdc.rs" />
      </div>
    </>
  )
}
