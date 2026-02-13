/**
 * Output Filter - Prevents leakage of private keys, seed phrases, and sensitive data.
 *
 * This is a mandatory pipeline stage. There is no API to bypass it.
 * Applied to: all AI text responses, tool outputs, log files, network requests.
 */

import type { OutputFilter, FilterResult, Redaction } from './types.js';
import { wordlists } from 'ethers/wordlists';

// BIP-39 English wordlist (2048 words). In production, this would be loaded from
// the full BIP-39 specification. Here we include the detection logic and a subset
// for pattern matching. The full wordlist is loaded at runtime.
const BIP39_WORD_COUNT = 2048;
const MNEMONIC_LENGTHS = [12, 15, 18, 21, 24];

// Common BIP-39 words that appear in regular English text, used to reduce false positives.
// If a sequence contains mostly non-common words from the BIP-39 list, it's more suspicious.
const COMMON_ENGLISH_OVERLAP = new Set([
  'about', 'above', 'across', 'action', 'actual', 'after', 'again', 'age',
  'all', 'also', 'among', 'and', 'anger', 'animal', 'annual', 'another',
  'any', 'april', 'area', 'army', 'around', 'art', 'away', 'baby', 'bag',
  'ball', 'base', 'basic', 'battle', 'beach', 'because', 'become', 'before',
  'begin', 'behind', 'below', 'best', 'better', 'between', 'beyond', 'bird',
  'black', 'blood', 'blue', 'board', 'body', 'book', 'both', 'bottom',
  'boy', 'brain', 'bring', 'brother', 'brown', 'build', 'bus', 'business',
  'call', 'camera', 'can', 'car', 'carbon', 'card', 'carry', 'case', 'cat',
  'caught', 'cause', 'certain', 'chair', 'change', 'charge', 'check',
  'child', 'choose', 'city', 'civil', 'claim', 'class', 'clean', 'climb',
  'close', 'club', 'coach', 'cold', 'color', 'column', 'come', 'common',
  'company', 'control', 'cool', 'corn', 'cost', 'country', 'couple',
  'course', 'cover', 'cross', 'cry', 'culture', 'cup', 'current', 'custom',
  'cycle', 'dad', 'damage', 'dance', 'day', 'deal', 'debate', 'decade',
  'decide', 'degree', 'design', 'detail', 'develop', 'device', 'dinner',
  'direct', 'display', 'doctor', 'dog', 'door', 'double', 'down', 'draw',
  'dream', 'drive', 'drop', 'during', 'dust', 'early', 'earth', 'east',
  'easy', 'economy', 'edge', 'effort', 'eight', 'either', 'element',
  'else', 'emotion', 'employ', 'end', 'enemy', 'energy', 'engine', 'enjoy',
  'enough', 'enter', 'entire', 'equal', 'error', 'escape', 'even',
  'evening', 'event', 'evidence', 'evil', 'example', 'exchange', 'excuse',
  'exercise', 'exist', 'expect', 'eye', 'face', 'fact', 'fall', 'family',
  'famous', 'fan', 'fat', 'father', 'fault', 'federal', 'feel', 'female',
  'few', 'field', 'film', 'final', 'find', 'fire', 'first', 'fish', 'fit',
  'flag', 'flight', 'floor', 'fly', 'follow', 'food', 'force', 'forest',
  'forget', 'fork', 'forward', 'found', 'fox', 'frame', 'free', 'friend',
  'from', 'front', 'fruit', 'fun', 'funny', 'future', 'game', 'garden',
  'gas', 'general', 'ghost', 'giant', 'gift', 'girl', 'give', 'glad',
  'glass', 'goat', 'gold', 'good', 'grace', 'grain', 'great', 'green',
  'group', 'grow', 'grunt', 'guard', 'guitar', 'gun', 'hair', 'half',
  'hand', 'happy', 'hard', 'hat', 'have', 'head', 'heart', 'heavy',
  'help', 'here', 'high', 'hold', 'home', 'horse', 'host', 'hotel',
  'hour', 'human', 'hundred', 'hunt', 'ice', 'idea', 'image', 'impact',
  'include', 'increase', 'index', 'indicate', 'indoor', 'initial', 'inner',
  'input', 'interest', 'into', 'iron', 'island', 'issue', 'item', 'january',
  'job', 'join', 'journey', 'joy', 'judge', 'just', 'keen', 'keep', 'key',
  'kid', 'kind', 'kitchen', 'knee', 'knife', 'know', 'labor', 'lady',
  'lamp', 'language', 'large', 'later', 'latin', 'laugh', 'law', 'layer',
  'leader', 'learn', 'leave', 'left', 'leg', 'legal', 'length', 'lesson',
  'letter', 'level', 'liberty', 'life', 'lift', 'light', 'limit', 'line',
  'link', 'list', 'little', 'live', 'long', 'look', 'love', 'low', 'lucky',
  'lunch', 'machine', 'main', 'major', 'make', 'man', 'manage', 'million',
  'mind', 'minute', 'mirror', 'miss', 'model', 'moment', 'monkey', 'month',
  'more', 'morning', 'mother', 'mountain', 'mouse', 'move', 'much', 'music',
  'must', 'myself', 'name', 'narrow', 'nation', 'nature', 'near', 'neck',
  'need', 'network', 'never', 'news', 'next', 'nice', 'night', 'noble',
  'normal', 'north', 'note', 'nothing', 'now', 'number', 'nurse', 'object',
  'occur', 'ocean', 'off', 'offer', 'office', 'often', 'oil', 'old', 'one',
  'only', 'open', 'option', 'orange', 'order', 'other', 'outdoor', 'outer',
  'output', 'outside', 'over', 'own', 'owner', 'page', 'pair', 'paper',
  'parent', 'park', 'part', 'party', 'pass', 'path', 'patient', 'pattern',
  'peace', 'people', 'pepper', 'person', 'phone', 'photo', 'piece', 'pilot',
  'pink', 'place', 'plan', 'play', 'please', 'point', 'pool', 'popular',
  'position', 'possible', 'post', 'power', 'practice', 'prepare', 'present',
  'pretty', 'price', 'pride', 'primary', 'print', 'problem', 'process',
  'produce', 'program', 'project', 'property', 'provide', 'public', 'pull',
  'push', 'put', 'quality', 'question', 'quick', 'race', 'radio', 'rain',
  'raise', 'range', 'rate', 'rather', 'raw', 'reach', 'ready', 'real',
  'reason', 'record', 'region', 'remain', 'remember', 'remove', 'report',
  'require', 'result', 'return', 'reveal', 'rich', 'right', 'ring', 'risk',
  'river', 'road', 'rock', 'room', 'round', 'route', 'rule', 'run', 'rural',
  'sad', 'safe', 'salt', 'same', 'sample', 'sand', 'say', 'scene', 'school',
  'science', 'screen', 'sea', 'search', 'season', 'second', 'secret',
  'section', 'security', 'seed', 'select', 'sell', 'senior', 'sense',
  'series', 'service', 'session', 'set', 'seven', 'shadow', 'share', 'she',
  'shift', 'ship', 'short', 'should', 'shoulder', 'show', 'side', 'sign',
  'silver', 'similar', 'simple', 'since', 'sister', 'site', 'six', 'size',
  'skill', 'skin', 'small', 'smart', 'smile', 'smoke', 'snow', 'social',
  'soldier', 'solid', 'solution', 'some', 'son', 'song', 'soon', 'sort',
  'sound', 'south', 'space', 'special', 'speed', 'spirit', 'split', 'sport',
  'spring', 'stage', 'stand', 'start', 'state', 'stay', 'step', 'still',
  'stock', 'stone', 'stop', 'story', 'street', 'strike', 'strong', 'student',
  'stuff', 'style', 'subject', 'such', 'sudden', 'sugar', 'summer', 'sun',
  'sure', 'surface', 'system', 'table', 'talk', 'target', 'task', 'tax',
  'teach', 'team', 'tell', 'term', 'test', 'text', 'thank', 'that', 'then',
  'there', 'they', 'thing', 'think', 'this', 'thought', 'three', 'throw',
  'time', 'today', 'together', 'tomorrow', 'tonight', 'too', 'tool', 'top',
  'total', 'toward', 'town', 'trade', 'travel', 'tree', 'trial', 'trip',
  'trouble', 'true', 'trust', 'truth', 'try', 'turn', 'twenty', 'two',
  'type', 'under', 'unit', 'until', 'upon', 'urban', 'use', 'used', 'usual',
  'valley', 'value', 'very', 'victory', 'village', 'voice', 'vote', 'wait',
  'walk', 'wall', 'want', 'war', 'warm', 'warn', 'wash', 'watch', 'water',
  'way', 'weapon', 'wear', 'weather', 'web', 'week', 'welcome', 'west',
  'what', 'when', 'where', 'which', 'while', 'white', 'who', 'wide', 'wife',
  'will', 'win', 'window', 'winter', 'wish', 'with', 'woman', 'wonder',
  'wood', 'word', 'work', 'world', 'worth', 'write', 'wrong', 'yard',
  'year', 'you', 'young', 'youth', 'zero', 'zone',
]);

const REDACTION_PLACEHOLDER = '[REDACTED BY WARDEX]';

function loadDefaultBip39Wordlist(): Set<string> {
  const words = new Set<string>();

  try {
    const english = wordlists.en;
    for (let i = 0; i < BIP39_WORD_COUNT; i++) {
      const word = english.getWord(i);
      if (typeof word === 'string' && word.length > 0) {
        words.add(word.toLowerCase());
      }
    }
  } catch {
    // Keep empty set fallback; heuristics still apply without full list.
  }

  return words;
}

const DEFAULT_BIP39_WORDLIST = loadDefaultBip39Wordlist();

/**
 * Detects hex-encoded private keys.
 * Secp256k1 private keys are 32 bytes = 64 hex characters.
 * Matches with or without 0x prefix.
 */
const PRIVATE_KEY_PATTERNS = [
  // 0x-prefixed 64 hex chars (standalone, not part of a longer hex string)
  /(?<![0-9a-fA-F])0x([0-9a-fA-F]{64})(?![0-9a-fA-F])/g,
  // Bare 64 hex chars that look like keys (surrounded by whitespace or quotes)
  /(?<=[\s"'`=:])([0-9a-fA-F]{64})(?=[\s"'`,;\]})])/g,
  // Standalone 64-hex line (common in logs/CLI output)
  /(?<=^|\n)\s*[0-9a-fA-F]{64}\s*(?=$|\n)/g,
  // Explicit key assignment forms (e.g. private_key=abcdef...)
  /\b(?:private[_\s-]?key|secret[_\s-]?key)\b\s*[:=]\s*["']?([0-9a-fA-F]{64})["']?/gi,
];

/**
 * Detects JSON keystore file patterns.
 */
const KEYSTORE_PATTERN = /\{[^}]*"crypto"\s*:\s*\{[^}]*"cipher"\s*:/gi;

/**
 * Detects sequences of words that could be BIP-39 mnemonics.
 * Looks for 12, 15, 18, 21, or 24 lowercase words separated by spaces.
 */
function findMnemonicSequences(
  text: string,
  bip39Wordlist: Set<string>
): Array<{ start: number; end: number }> {
  const results: Array<{ start: number; end: number }> = [];

  // Split text into words and track positions
  const wordPattern = /\b[a-zA-Z]{3,8}\b/g;
  let match: RegExpExecArray | null;
  const words: Array<{ word: string; start: number; end: number }> = [];

  while ((match = wordPattern.exec(text)) !== null) {
    words.push({
      word: match[0].toLowerCase(),
      start: match.index,
      end: match.index + match[0].length,
    });
  }

  // Check sliding windows of mnemonic lengths
  for (const mnemonicLength of MNEMONIC_LENGTHS) {
    for (let i = 0; i <= words.length - mnemonicLength; i++) {
      const window = words.slice(i, i + mnemonicLength);
      const windowWords = window.map((w) => w.word);
      const inBip39 = windowWords.filter((w) => bip39Wordlist.has(w)).length;

      // Count how many words are NOT common English words
      // (BIP-39 has many uncommon words like "abandon", "velvet", "coyote")
      const uncommonCount = windowWords.filter(
        (w) => !COMMON_ENGLISH_OVERLAP.has(w)
      ).length;

      // Heuristic: if more than 40% of words are uncommon AND the words
      // are consecutive (close together in the text), flag as potential mnemonic
      const isConsecutive =
        window[window.length - 1].end - window[0].start <
        mnemonicLength * 12; // ~12 chars per word max

      // Strong detection if we have a real BIP-39 list and most words match it.
      const strongBip39Match =
        bip39Wordlist.size >= BIP39_WORD_COUNT &&
        inBip39 >= Math.ceil(mnemonicLength * 0.9) &&
        isConsecutive;
      // Heuristic fallback when full list is unavailable.
      const heuristicMatch =
        uncommonCount >= mnemonicLength * 0.4 &&
        isConsecutive;

      if (strongBip39Match || heuristicMatch) {
        results.push({
          start: window[0].start,
          end: window[window.length - 1].end,
        });
      }
    }
  }

  return results;
}

/**
 * Creates the mandatory output filter.
 * This filter cannot be disabled or bypassed.
 */
export function createOutputFilter(
  bip39Wordlist?: Set<string>
): OutputFilter {
  const wordlist = bip39Wordlist ?? DEFAULT_BIP39_WORDLIST;

  return {
    filterText(text: string): FilterResult {
      const redactions: Redaction[] = [];
      let filtered = text;
      let blocked = false;

      // 1. Detect private keys
      for (const pattern of PRIVATE_KEY_PATTERNS) {
        // Clone the pattern per invocation to avoid shared lastIndex state.
        const localPattern = new RegExp(pattern.source, pattern.flags);
        let keyMatch: RegExpExecArray | null;

        while ((keyMatch = localPattern.exec(text)) !== null) {
          redactions.push({
            type: 'private_key',
            start: keyMatch.index,
            end: keyMatch.index + keyMatch[0].length,
            replacement: REDACTION_PLACEHOLDER,
          });
        }
      }

      // 2. Detect seed phrases / mnemonics
      const mnemonicMatches = findMnemonicSequences(text, wordlist);
      for (const match of mnemonicMatches) {
        redactions.push({
          type: 'seed_phrase',
          start: match.start,
          end: match.end,
          replacement: REDACTION_PLACEHOLDER,
        });
      }

      // 3. Detect keystore file patterns
      // Clone the pattern per invocation to avoid shared lastIndex state.
      const keystorePattern = new RegExp(KEYSTORE_PATTERN.source, KEYSTORE_PATTERN.flags);
      let keystoreMatch: RegExpExecArray | null;
      while ((keystoreMatch = keystorePattern.exec(text)) !== null) {
        redactions.push({
          type: 'keystore',
          start: keystoreMatch.index,
          end: keystoreMatch.index + keystoreMatch[0].length,
          replacement: REDACTION_PLACEHOLDER,
        });
        // If a full keystore is being output, block the entire response
        blocked = true;
      }

      // Apply redactions (from end to start to preserve indices)
      const sortedRedactions = [...redactions].sort(
        (a, b) => b.start - a.start
      );
      for (const redaction of sortedRedactions) {
        filtered =
          filtered.slice(0, redaction.start) +
          redaction.replacement +
          filtered.slice(redaction.end);
      }

      return { filtered, redactions, blocked };
    },

    filterData(data: unknown): FilterResult {
      // Recursively convert to string, filter, then note what changed
      const serialized = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
      return this.filterText(serialized);
    },
  };
}
