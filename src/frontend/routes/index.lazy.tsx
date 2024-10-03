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
      <Link to="/get_batch_balances">
        <button>get_batch_balances([address1, address2])</button>
      </Link>
      <Link to="/sign_message">
        <button>sign_message(message)</button>
      </Link>
      <Link to="/send_eth_with_fillers">
        <button>send_eth_with_fillers()</button>
      </Link>
    </div>
  );
}