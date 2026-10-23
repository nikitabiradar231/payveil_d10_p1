export const STEALTH_ANNOUNCER_ABI = [
  {
    type: 'function',
    name: 'announce',
    inputs: [
      { name: 'schemeId', type: 'uint256', internalType: 'uint256' },
      { name: 'stealthAddress', type: 'address', internalType: 'address' },
      { name: 'ephemeralPubKey', type: 'bytes', internalType: 'bytes' },
      { name: 'metadata', type: 'bytes', internalType: 'bytes' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'event',
    name: 'Announcement',
    inputs: [
      { name: 'schemeId', type: 'uint256', indexed: true, internalType: 'uint256' },
      { name: 'stealthAddress', type: 'address', indexed: true, internalType: 'address' },
      { name: 'caller', type: 'address', indexed: true, internalType: 'address' },
      { name: 'ephemeralPubKey', type: 'bytes', indexed: false, internalType: 'bytes' },
      { name: 'metadata', type: 'bytes', indexed: false, internalType: 'bytes' }
    ],
    anonymous: false
  }
] as const;

export const STEALTH_PAYMENT_ABI = [
  {
    type: 'constructor',
    inputs: [{ name: '_announcer', type: 'address', internalType: 'address' }],
    stateMutability: 'nonpayable'
  },
  {
    type: 'receive',
    stateMutability: 'payable'
  },
  {
    type: 'function',
    name: 'announcer',
    inputs: [],
    outputs: [{ name: '', type: 'address', internalType: 'contract IERC5564Announcer' }],
    stateMutability: 'view'
  },
  {
    type: 'function',
    name: 'payETH',
    inputs: [
      { name: 'schemeId', type: 'uint256', internalType: 'uint256' },
      { name: 'stealthAddress', type: 'address', internalType: 'address payable' },
      { name: 'ephemeralPubKey', type: 'bytes', internalType: 'bytes' },
      { name: 'metadata', type: 'bytes', internalType: 'bytes' }
    ],
    outputs: [],
    stateMutability: 'payable'
  },
  {
    type: 'event',
    name: 'StealthPaymentSent',
    inputs: [
      { name: 'schemeId', type: 'uint256', indexed: true, internalType: 'uint256' },
      { name: 'stealthAddress', type: 'address', indexed: true, internalType: 'address' },
      { name: 'payer', type: 'address', indexed: true, internalType: 'address' },
      { name: 'amount', type: 'uint256', indexed: false, internalType: 'uint256' },
      { name: 'ephemeralPubKey', type: 'bytes', indexed: false, internalType: 'bytes' },
      { name: 'metadata', type: 'bytes', indexed: false, internalType: 'bytes' }
    ],
    anonymous: false
  }
] as const;
