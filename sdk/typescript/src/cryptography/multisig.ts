// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { toB64 } from '@mysten/bcs';
import { SIGNATURE_SCHEME_TO_FLAG, SerializedSignature, SignaturePubkeyPair, SignatureScheme, fromSerializedSignature } from './signature';
import { PublicKey } from './publickey';
import { blake2b } from '@noble/hashes/blake2b';
import { bytesToHex } from '@noble/hashes/utils';
import RoaringBitmap32 from 'roaring/RoaringBitmap32';

import { normalizeSuiAddress, SUI_ADDRESS_LENGTH } from '../types';
import { Ed25519PublicKey, Secp256k1PublicKey, builder, fromB64 } from '..';
import {
  object,
  array,
  Infer,
  integer,
  string,
} from 'superstruct';

export type PubkeyWeightPair = {
  pubKey: PublicKey;
  weight: number;
};

export type CompressedSignature = { kind: SignatureScheme, val: number[]}

export const PkWeightPair = object({
    str: string(),
    u8: integer(),
  });
  export type PkWeightPair = Infer<typeof PkWeightPair>;

export const MultiSigPublicKey = object({
  pk_map: array(PkWeightPair),
  threshold: array(integer()),
});

export type MultiSigPublicKey = Infer<typeof MultiSigPublicKey>;

export type MultiSig = {
  sigs: CompressedSignature[],
  bitmap: number[],
  multisig_pk: MultiSigPublicKey,
}
export function toMultiSigAddress(
  pks: PubkeyWeightPair[],
  threshold: Uint8Array,
  ): string {
    let maxLength = 1 + 64 * 10 + 1 * 10 + 2;
    let tmp = new Uint8Array(maxLength);
    tmp.set([SIGNATURE_SCHEME_TO_FLAG['MultiSig']]);
    tmp.set(threshold, 1);
    let i = 3;
    for (const pk of pks) {
      tmp.set(pk.pubKey.flag(), i);
      tmp.set(pk.pubKey.toBytes(), i + 1);
      tmp.set([pk.weight], i + 1 + pk.pubKey.toBytes().length);
      i += pk.pubKey.toBytes().length + 2;
    }
    return normalizeSuiAddress(
      bytesToHex(blake2b(tmp.slice(0, i), { dkLen: 32 })).slice(0, SUI_ADDRESS_LENGTH * 2),
    );
}

export function combinePartialSigs(
  pairs: SerializedSignature[],
  pks: PubkeyWeightPair[],
  threshold: Uint8Array
): SerializedSignature {
  let multisig_pk: MultiSigPublicKey = {
    pk_map: pks.map((x) => toPkWeightPair(x)),
    threshold: Array.from(threshold.map((x) => Number(x))),
  };
  let bytes1 = builder.ser('MultiSigPublicKey', multisig_pk).toBytes();
  console.log('111bytes MultiSigPublicKey', toB64(bytes1));

  const bitmap3 = new RoaringBitmap32();
  let compressed_sigs: CompressedSignature[] = new Array(pairs.length);
  for (let i = 0; i < pairs.length; i++) {
    let parsed = fromSerializedSignature(pairs[i]);
    let v = Array.from(parsed.signature.map((x) => Number(x)));
    console.log('v', v);
    compressed_sigs[i] = {
      kind: parsed.signatureScheme,
      val: v,
    };

    // console.log('bytes CompressedSignature', bytes);
    for (let j = 0; j < pks.length; j++) {
      if (parsed.pubKey.equals(pks[j].pubKey)) {
        bitmap3.add(j);
        break;
      }
    }
  }
  let multisig: MultiSig = {
    sigs: compressed_sigs,
    bitmap: bitmap3.toArray(),
    multisig_pk: multisig_pk,
  }; 
  console.log('multisig', multisig);
  console.log('multisig_pk', multisig_pk);

  const bytes = builder.ser('MultiSig', multisig).toBytes();
  let tmp = new Uint8Array(bytes.length + 1);
  tmp.set([SIGNATURE_SCHEME_TO_FLAG['MultiSig']]);
  tmp.set(bytes, 1);
  console.log('multisig bytes', toB64(tmp));
  return toB64(tmp);
}

export function decodeMultiSig(signature: string): SignaturePubkeyPair[] {
    const parsed = fromB64(signature);
    if (parsed.length < 1 || parsed[0] !== SIGNATURE_SCHEME_TO_FLAG['MultiSig']) {
      throw new Error('Invalid MultiSig flag');
    };
    console.log('parsed.slice(1)', parsed.slice(1));

    const multisig: MultiSig = builder.de('MultiSig', parsed.slice(1));
    console.log('multisig', multisig);
    let res: SignaturePubkeyPair[] = new Array(multisig.sigs.length);
    for (let i = 0; i < multisig.sigs.length; i++) {
      let s: CompressedSignature = multisig.sigs[i];
      let pk_index = multisig.bitmap.at(i);
      let scheme = s.kind;
      let pk_str = multisig.multisig_pk.pk_map[pk_index as number].str;
      const PublicKey = scheme === 'Ed25519' ? Ed25519PublicKey : Secp256k1PublicKey;

      res[i] = {
          signatureScheme: scheme,
          signature: Uint8Array.from(s.val),
          pubKey: new PublicKey(fromB64(pk_str)),
        };
    }
    return res;
  }

  // export function to_serialize_pk_map(pks: PubkeyWeightPair[]): number[][] {
  //   let res: number[][] = new Array(pks.length);
  //   for (let i = 0; i < pks.length; i++) {
  //     let arr = new Uint8Array(pks[i].pubKey.toBytes().length + 1);
  //     arr.set(pks[i].pubKey.toBytes());
  //     arr.set([pks[i].weight], pks[i].pubKey.toBytes().length);
  //     res[i] = Array.from(arr.map((x) => Number(x)));
  //   }
  //   return res;
  // }

  export function toPkWeightPair(pk: PubkeyWeightPair): PkWeightPair {
    return {
      str: pk.pubKey.toBase64(),
      u8: pk.weight,
    };
  }