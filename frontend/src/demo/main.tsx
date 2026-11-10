import React from 'react';
import ReactDOM from 'react-dom/client';
import { enableLocalDemoTransport } from '../api/client';
import { AppRoutes } from '../routes/AppRoutes';
import { DemoProvider } from './Provider';
import { DemoFrame } from './DemoFrame';
import { DemoLogin } from './DemoLogin';
import '../index.css';
import './demo.css';

const root = ReactDOM.createRoot(document.getElementById('root')!);
try {
  const baseURL = import.meta.env.VITE_DEMO_API_BASE_URL;
  if (typeof baseURL !== 'string' || !baseURL) throw new Error('Explicit demo API configuration is required.');
  if (location.protocol !== 'https:' || !['localhost', '127.0.0.1', '[::1]'].includes(location.hostname))
    throw new Error('The demo frontend requires loopback HTTPS.');
  if (new URL(baseURL).hostname !== location.hostname) throw new Error('Use the same hostname for frontend and demo API.');
  enableLocalDemoTransport(baseURL);
  root.render(<React.StrictMode><DemoFrame><DemoProvider><AppRoutes hashRouting loginElement={<DemoLogin />} /></DemoProvider></DemoFrame></React.StrictMode>);
} catch {
  root.render(<DemoFrame><main className="demo-configuration-error"><h1>Local demo configuration required</h1>
    <p>Open this entry over loopback HTTPS and configure VITE_DEMO_API_BASE_URL with the explicitly selected loopback HTTPS demo backend. Normal GNOSIS authentication is not used as a fallback.</p></main></DemoFrame>);
}
