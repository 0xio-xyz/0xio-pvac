declare module 'tweetnacl' {
  const nacl: {
    scalarMult: ((n: Uint8Array, p: Uint8Array) => Uint8Array) & { base(n: Uint8Array): Uint8Array };
  };
  export default nacl;
}
