interface BackLayer {
  token: number;
  close: () => void;
}

const layers: BackLayer[] = [];
let nextToken = 0;
let installed = false;

function currentToken(): number | undefined {
  const state = window.history.state as { authBackToken?: number } | null;
  return state?.authBackToken;
}

function install(): void {
  if (installed || typeof window === 'undefined') {
    return;
  }
  installed = true;
  window.addEventListener('popstate', () => {
    const layer = layers[layers.length - 1];
    // Landing back on the top layer's own entry means nothing left the stack.
    if (!layer || currentToken() === layer.token) {
      return;
    }
    layers.pop();
    layer.close();
  });
}

/**
 * Treats the browser back gesture as "close the topmost overlay". Each push
 * marks its history entry with a token; the returned release function removes
 * the layer and consumes its entry while the entry is still current. Without
 * open layers the back gesture keeps its normal meaning, so users can still
 * leave the page.
 */
export function pushBackLayer(close: () => void): () => void {
  if (typeof window === 'undefined') {
    return () => {};
  }

  install();
  const layer: BackLayer = { token: ++nextToken, close };
  layers.push(layer);
  window.history.pushState({ authBackToken: layer.token }, '');

  return () => {
    const index = layers.indexOf(layer);
    if (index === -1) {
      return;
    }
    layers.splice(index, 1);
    if (index === layers.length && currentToken() === layer.token) {
      window.history.back();
    }
  };
}
