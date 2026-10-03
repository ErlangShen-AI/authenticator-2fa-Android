interface BackLayer {
  close: () => void;
}

const layers: BackLayer[] = [];
let installed = false;
let consumedPops = 0;

function install(): void {
  if (installed) {
    return;
  }
  installed = true;
  window.addEventListener('popstate', () => {
    // A pop consumed by an explicit close belongs to that close, not to the
    // user's back gesture.
    if (consumedPops > 0) {
      consumedPops -= 1;
      return;
    }
    layers.pop()?.close();
  });
}

/**
 * Treats the browser back gesture as "close the topmost overlay". Each push
 * adds one history entry; the returned release function removes the layer and
 * consumes its entry while the layer still owns it. Without open layers the
 * back gesture keeps its normal meaning, so users can still leave the page.
 */
export function pushBackLayer(close: () => void): () => void {
  if (typeof window === 'undefined') {
    return () => {};
  }

  install();
  const layer: BackLayer = { close };
  layers.push(layer);
  window.history.pushState({ authBackLayer: true }, '');

  return () => {
    const index = layers.indexOf(layer);
    if (index === -1) {
      return;
    }
    layers.splice(index, 1);
    if (index === layers.length && window.history.state?.authBackLayer) {
      consumedPops += 1;
      window.history.back();
    }
  };
}
