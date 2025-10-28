import { mapErrorToMessage } from './errorMap.js';

describe('mapErrorToMessage', () => {
  it('redacts tokens', () => {
    const msg = mapErrorToMessage({ message: 'access_token=abc refresh_token=xyz client_secret=foo' });
    expect(msg).not.toContain('abc');
    expect(msg).not.toContain('xyz');
    expect(msg).not.toContain('foo');
  });
  it('handles status mappings', () => {
    expect(mapErrorToMessage({ response: { status: 401 } })).toMatch(/Unauthorized/);
    expect(mapErrorToMessage({ response: { status: 429 } })).toMatch(/Rate limit/);
  });
});


