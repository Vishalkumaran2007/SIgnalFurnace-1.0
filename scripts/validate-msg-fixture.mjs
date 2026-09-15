import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import MsgReaderModule from "@kenjiuno/msgreader";

const fixturePath = "/home/ubuntu/sih26106-cyber-forensics/.test-fixtures/benign-test.msg";
const buffer = await readFile(fixturePath);
const signature = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
if (!buffer.subarray(0, signature.length).equals(signature)) throw new Error("Fixture is not an Outlook compound-file message.");
const MsgReader = MsgReaderModule.default ?? MsgReaderModule;
const reader = new MsgReader(Uint8Array.from(buffer).buffer);
const message = reader.getFileData();
const result = {
  bytes: buffer.byteLength,
  sha256: createHash("sha256").update(buffer).digest("hex"),
  subject: String(message.subject || ""),
  hasBody: Boolean(message.body || message.html),
  attachmentCount: Array.isArray(message.attachments) ? message.attachments.length : 0,
};
if (!result.subject && !result.hasBody) throw new Error("Parsed MSG fixture contains neither subject nor body.");
console.log(JSON.stringify(result));
