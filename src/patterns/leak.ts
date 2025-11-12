import type { Pattern } from "../types";

/**
 * Patterns for system prompt leak attacks
 * These detect attempts to extract the system prompt or initial instructions
 */
export const leakPatterns: Pattern[] = [
  // "repeat/reveal/show (me) (the) (system/initial/original) (prompt/instructions)"
  {
    regex:
      /\b(?:repeat|reveal|show|tell\s+me|display|output|print)\s+(?:me\s+)?(?:the\s+)?(?:your\s+)?(?:system|initial|original|above|previous)?\s*(?:prompt|instructions|guidelines|rules|directives)\b/i,
    severity: 0.95,
    type: "systemPromptLeak",
  },
  // "what (were/are) (your/the) (original) (instructions/guidelines/rules)"
  {
    regex:
      /\bwhat\s+(?:were|are|is)\s+(?:your|the)\s+(?:original\s+)?(?:instructions|guidelines|rules|directives|prompt)\b/i,
    severity: 0.9,
    type: "systemPromptLeak",
  },
  // "print/output/display (your/the) (system) (prompt/instructions)"
  {
    regex:
      /\b(?:print|output|display|show|reveal)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions|guidelines|rules)\b/i,
    severity: 0.95,
    type: "systemPromptLeak",
  },
  // "what is your system prompt"
  {
    regex: /\bwhat\s+(?:is|was)\s+your\s+system\s+prompt\b/i,
    severity: 0.95,
    type: "systemPromptLeak",
  },
  // "tell me about your instructions"
  {
    regex:
      /\btell\s+me\s+about\s+your\s+(?:instructions|guidelines|rules|directives|prompt)\b/i,
    severity: 0.85,
    type: "systemPromptLeak",
  },
  // "how were you configured"
  {
    regex:
      /\bhow\s+were\s+you\s+(?:configured|programmed|instructed|set\s+up)\b/i,
    severity: 0.8,
    type: "systemPromptLeak",
  },
  // "what are you not allowed to do"
  {
    regex:
      /\bwhat\s+(?:are|were)\s+you\s+(?:not\s+)?(?:allowed|forbidden|prohibited|told)\s+to\s+(?:do|say)\b/i,
    severity: 0.75,
    type: "systemPromptLeak",
  },
  // "fence/format/wrap the prompt in markdown/code/text block"
  {
    regex:
      /\b(?:fence|format|wrap|enclose|put)\s+(?:the\s+)?(?:above\s+)?(?:prompt|instructions|content|text)\s+(?:in|inside|within)\s+(?:a\s+)?(?:markdown|code|text|raw)\s*(?:block|fence)?\b/i,
    severity: 0.9,
    type: "systemPromptLeak",
  },
  // "re-transcript/transcribe/copy the above content/text/prompt"
  {
    regex:
      /\b(?:re-?transcript|re-?transcribe|copy|reproduce|replicate|duplicate)\s+(?:the\s+)?(?:above|previous|prior)\s+(?:content|text|prompt|instructions|message|conversation)\b/i,
    severity: 0.9,
    type: "systemPromptLeak",
  },
  // "output/return/give the above/previous (in) format"
  {
    regex:
      /\b(?:output|return|give|provide)\s+(?:the\s+)?(?:above|previous|prior)\s+(?:content|text|prompt|instructions|message)?\s*(?:in|inside|as)?\s*(?:markdown|code|text|raw|verbatim)?\b/i,
    severity: 0.85,
    type: "systemPromptLeak",
  },
  // "repeat (all) (previous/prior) (messages/conversation)"
  {
    regex:
      /\brepeat\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|earlier|past)\s+(?:messages?|conversations?|inputs?|prompts?|exchanges?)\b/i,
    severity: 0.9,
    type: "systemPromptLeak",
  },
  // "what did (the) (last/previous/other) user(s) (ask/say)"
  {
    regex:
      /\bwhat\s+did\s+(?:the\s+)?(?:last|previous|prior|other|earlier)\s+(?:users?|persons?|people)\s+(?:ask|say|tell|request|want)\b/i,
    severity: 0.85,
    type: "systemPromptLeak",
  },
  // "show/display (me) (the) conversation history/log/messages"
  {
    regex:
      /\b(?:show|display)\s+(?:me\s+)?(?:the\s+)?(?:full\s+)?(?:conversation|chat|message|dialogue|earlier)\s+(?:history|log|record|transcript|messages)\b/i,
    severity: 0.9,
    type: "systemPromptLeak",
  },
  // "display the message/chat transcript"
  {
    regex:
      /\bdisplay\s+(?:the\s+)?(?:message|chat|conversation)\s+(?:transcript|history|log|record)\b/i,
    severity: 0.9,
    type: "systemPromptLeak",
  },
  // "summarize (everything) (we've) discussed"
  {
    regex:
      /\bsummarize\s+(?:everything|all)\s+(?:we've|we\s+have|that\s+we've|that\s+we\s+have)\s+(?:discussed|talked\s+about|covered)\b/i,
    severity: 0.8,
    type: "systemPromptLeak",
  },
  // "print (all) (prior/previous) (inputs/messages)"
  {
    regex:
      /\bprint\s+(?:all\s+)?(?:prior|previous|past|earlier)\s+(?:inputs?|messages?|prompts?|conversations?|exchanges?)\b/i,
    severity: 0.9,
    type: "systemPromptLeak",
  },
];
