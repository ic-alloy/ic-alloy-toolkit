import { Outlet, createRootRoute } from '@tanstack/react-router';

import alloyLogo from '../assets/alloy.png';
import icLogo from '../assets/ic.svg';

export const Route = createRootRoute({
  component: Root,
});

function Root() {
  return (
    <main>
      <div>
        <a href="https://alloy.rs" target="_blank" rel="noreferrer">
          <img src={alloyLogo} className="logo" alt="Vite logo" />
        </a>
        <a href="https://internetcomputer.org" target="_blank" rel="noreferrer">
          <img src={icLogo} className="logo" alt="React logo" />
        </a>
      </div>
      <h1>Alloy + ICP</h1>
      <p>
        This app is a toolkit to showcase examples on how to use{' '}
        <a
          href="https://github.com/alloy-rs/alloy"
          target="_blank"
          rel="noreferrer"
        >
          Alloy
        </a>{' '}
        in ICP canisters to simplify interactions with Ethereum. It uses the{' '}
        <a
          href="https://github.com/ic-alloy/ic-alloy"
          target="_blank"
          rel="noreferrer"
        >
          ic-alloy
        </a>{' '}
        fork that adds ICP as a signer and provider.
      </p>

      <Outlet />

      <div className="links">
        <a
          href="https://github.com/ic-alloy/ic-alloy-toolkit/graphs/contributors"
          target="_blank"
          rel="noreferrer"
        >
          <img src="https://img.shields.io/github/contributors/ic-alloy/ic-alloy-toolkit.svg?style=for-the-badge" />
        </a>
        <a
          href="https://github.com/ic-alloy/ic-alloy-toolkit"
          target="_blank"
          rel="noreferrer"
        >
          <img src="https://img.shields.io/github/license/ic-alloy/ic-alloy-toolkit.svg?style=for-the-badge" />
        </a>
        <a
          href="https://github.com/ic-alloy/ic-alloy-toolkit/stargazers"
          target="_blank"
          rel="noreferrer"
        >
          <img src="https://img.shields.io/github/stars/ic-alloy/ic-alloy-toolkit?style=for-the-badge" />
        </a>
      </div>
    </main>
  );
}
