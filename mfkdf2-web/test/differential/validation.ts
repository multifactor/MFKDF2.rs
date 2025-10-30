function bufferEqual(a: unknown, b: unknown): boolean {
  if (a == null || b == null) return false;
  const ba = Buffer.from(a as any);
  const bb = Buffer.from(b as any);
  if (ba.byteLength !== bb.byteLength) return false;
  return ba.equals(bb);
}

function bufferArrayEqual(a: unknown, b: unknown): boolean {
  if (!Array.isArray(a) || !Array.isArray(b)) return false;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (!bufferEqual(a[i], b[i])) return false;
  }
  return true;
}

function numbersClose(a: number, b: number, eps = 1): boolean {
  return Math.abs(a - b) <= eps;
}

function isPolicyFactorEqual(a: any, b: any): boolean {
  if (a.id !== b.id) {
    console.error('policy factor id mismatch', a.id, b.id);
    return false;
  }
  if (a.type !== b.type) {
    console.error('policy factor type mismatch', a.type, b.type);
    return false;
  }
  if (JSON.stringify(a.params) !== JSON.stringify(b.params)) {
    console.error('policy factor params mismatch', a.params, b.params);
    return false;
  }
  if (a.salt !== b.salt) {
    console.error('policy factor salt mismatch', a.salt, b.salt);
    return false;
  }
  if (a.secret !== b.secret) {
    console.error('policy factor secret mismatch', a.secret, b.secret);
    return false;
  }
  if (a.pad !== b.pad) {
    console.error('policy factor pad mismatch', a.pad, b.pad);
    return false;
  }
  if (a.hint !== b.hint) {
    console.error('policy factor hint mismatch', a.hint, b.hint);
    return false;
  }
  return true;
}

function isPolicyEqual(a: any, b: any): boolean {
  if (a.threshold !== b.threshold) {
    console.error('policy threshold mismatch', a.threshold, b.threshold);
    return false;
  }
  if (a.salt !== b.salt) {
    console.error('policy salt mismatch', a.salt, b.salt);
    return false;
  }
  if (a.hmac !== b.hmac) {
    console.error('policy hmac mismatch', a.hmac, b.hmac);
    return false;
  }
  if (a.time !== b.time) {
    console.error('policy time mismatch', a.time, b.time);
    return false;
  }
  if (a.memory !== b.memory) {
    console.error('policy memory mismatch', a.memory, b.memory);
    return false;
  }
  if (a.key !== b.key) {
    console.error('policy key mismatch', a.key, b.key);
    return false;
  }
  if (a.factors.length !== b.factors.length) {
    console.error('policy factors length mismatch', a.factors.length, b.factors.length);
    return false;
  }
  for (let i = 0; i < a.factors.length; i++) {
    if (!isPolicyFactorEqual(a.factors[i], b.factors[i])) return false;
  }
  return true;
}

function derivedKeyIsEqual(a: any, b: any): boolean {
  if (!a || !b) return false;
  if (!isPolicyEqual(a.policy, b.policy)) {
    console.error('policy mismatch', a.policy, b.policy);
    return false;
  }
  if (!bufferEqual(a.key, b.key)) {
    console.error('key mismatch', a.key, b.key);
    return false;
  }
  if (!bufferEqual(a.secret, b.secret)) {
    console.error('secret mismatch', a.secret, b.secret);
    return false;
  }
  if (!bufferArrayEqual(a.shares || [], b.shares || [])) {
    console.error('shares mismatch', a.shares, b.shares);
    return false;
  }
  if (a.entropyBits && b.entropyBits) {
    if (a.entropyBits.theoretical !== b.entropyBits.theoretical) {
      console.error('entropy theoretical mismatch', a.entropyBits.theoretical, b.entropyBits.theoretical);
      return false;
    }
    if (!numbersClose(a.entropyBits.real, b.entropyBits.real)) {
      console.error('entropy mismatch', a.entropyBits.real, b.entropyBits.real);
      return false;
    }
  }
  return true;
}

export { derivedKeyIsEqual };