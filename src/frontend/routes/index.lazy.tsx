import { Link, createLazyFileRoute } from "@tanstack/react-router";

export const Route = createLazyFileRoute("/")({
  component: Index,
});

function Index() {
  return (
    <div className="menu">
      <Link to="/get_address">
        <button>get_address()</button>
      </Link>
      <Link to="/get_latest_block">
        <button>get_latest_block()</button>
      </Link>
      <Link to="/get_balance">
        <button>get_balance(address)</button>
      </Link>
      <Link to="/get_balance_usdc">
        <button>get_balance_usdc(address)</button>
      </Link>
      <Link to="/get_batch_balances">
        <button>get_batch_balances([address1, address2])</button>
      </Link>
      <Link to="/sign_message">
        <button>sign_message(message)</button>
      </Link>
      <Link to="/send_eth">
        <button>send_eth()</button>
      </Link>
      <Link to="/send_eth_with_fillers">
        <button>send_eth_with_fillers()</button>
      </Link>
      <Link to="/transfer_usdc">
        <button>transfer_usdc()</button>
      </Link>
      <Link to="/watch_blocks">
        <button>watch_blocks()</button>
      </Link>
      <Link to="/watch_usdc_transfer">
        <button>watch_usdc_transfer()</button>
      </Link>
    </div>
  );
}
