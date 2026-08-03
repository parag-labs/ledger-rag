// LedgerRAG cross-language verifier (C# / .NET 8)
//
// Purpose: independently verify a QueryResponse produced by the Python LedgerRAG
// server -- using a DIFFERENT language and crypto stack. If this passes, it proves
// the verifiability is standards-based and real, not a Python-specific trick.
//
// It reproduces exactly the Python hashing/signing rules:
//   leaf hash  = SHA256(0x00 || utf8(text))
//   node hash  = SHA256(0x01 || left || right)
//   root msg   = root || prev_root(optional) || leaf_count (8 bytes, big-endian)
//   signature  = Ed25519 over root msg, verified with the raw public key

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace LedgerRag.Verifier;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("usage: ledgerrag-verify <response.json>");
            return 2;
        }

        var json = File.ReadAllText(args[0]);
        var resp = JsonSerializer.Deserialize<QueryResponse>(json, JsonOpts)
                   ?? throw new InvalidOperationException("could not parse response");

        var result = Verify.VerifyResponse(resp);
        Console.WriteLine(result.Verified ? "\u2705 VERIFIED (C#)" : "\u274c TAMPERED / INVALID (C#)");
        Console.WriteLine($"  signature_ok = {result.SignatureOk}");
        foreach (var c in result.Chunks)
            Console.WriteLine($"  chunk {c.ChunkId}: hash_ok={c.HashOk} inclusion_ok={c.InclusionOk}");

        return result.Verified ? 0 : 1;
    }

    internal static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };
}

internal static class Hashing
{
    public static byte[] HashLeaf(byte[] data)
    {
        var buf = new byte[data.Length + 1];
        buf[0] = 0x00;
        Array.Copy(data, 0, buf, 1, data.Length);
        return SHA256.HashData(buf);
    }

    public static byte[] HashNodes(byte[] left, byte[] right)
    {
        var buf = new byte[left.Length + right.Length + 1];
        buf[0] = 0x01;
        Array.Copy(left, 0, buf, 1, left.Length);
        Array.Copy(right, 0, buf, 1 + left.Length, right.Length);
        return SHA256.HashData(buf);
    }
}

internal static class Verify
{
    public static VerificationResult VerifyResponse(QueryResponse resp)
    {
        var sr = resp.SignedRoot;
        var root = Hex.Decode(sr.Root);
        var prev = string.IsNullOrEmpty(sr.PrevRoot) ? Array.Empty<byte>() : Hex.Decode(sr.PrevRoot!);
        var leafCountBytes = ToBigEndian8(sr.LeafCount);

        // root message = root || prev_root || leaf_count(8 big-endian)
        var msg = new byte[root.Length + prev.Length + 8];
        Array.Copy(root, 0, msg, 0, root.Length);
        Array.Copy(prev, 0, msg, root.Length, prev.Length);
        Array.Copy(leafCountBytes, 0, msg, root.Length + prev.Length, 8);

        var sigOk = VerifyEd25519(Hex.Decode(sr.PublicKey), msg, Hex.Decode(sr.Signature));

        var chunkResults = new List<ChunkResult>();
        var allOk = sigOk;
        foreach (var proof in resp.Proofs)
        {
            var text = resp.Citations.First(c => c.ChunkId == proof.ChunkId).Text;
            var leafBytes = Encoding.UTF8.GetBytes(text);

            var recomputed = Convert.ToHexString(SHA256.HashData(leafBytes)).ToLowerInvariant();
            var hashOk = recomputed == proof.Sha256;

            var inclusionOk = VerifyInclusion(leafBytes, proof.MerklePath, root);
            var ok = hashOk && inclusionOk;
            allOk &= ok;
            chunkResults.Add(new ChunkResult(proof.ChunkId, hashOk, inclusionOk));
        }

        return new VerificationResult(allOk, sigOk, chunkResults);
    }

    private static bool VerifyInclusion(byte[] leafData, List<ProofStep> path, byte[] root)
    {
        var computed = Hashing.HashLeaf(leafData);
        foreach (var step in path)
        {
            var sibling = Hex.Decode(step.Sibling);
            computed = step.Side == "left"
                ? Hashing.HashNodes(sibling, computed)
                : Hashing.HashNodes(computed, sibling);
        }
        return computed.AsSpan().SequenceEqual(root);
    }

    private static bool VerifyEd25519(byte[] publicKey, byte[] message, byte[] signature)
    {
        var verifier = new Ed25519Signer();
        verifier.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
        verifier.BlockUpdate(message, 0, message.Length);
        return verifier.VerifySignature(signature);
    }

    private static byte[] ToBigEndian8(long value)
    {
        var b = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian) Array.Reverse(b);
        return b;
    }
}

internal static class Hex
{
    public static byte[] Decode(string hex) => Convert.FromHexString(hex);
}

// ---- DTOs matching the Python QueryResponse schema ----
internal sealed record QueryResponse(
    string Answer,
    List<Citation> Citations,
    List<Proof> Proofs,
    SignedRoot SignedRoot);

internal sealed record Citation(string ChunkId, string DocId, int Seq, string Text);

internal sealed record Proof(string ChunkId, int LeafIndex, string Sha256, List<ProofStep> MerklePath);

internal sealed record ProofStep(string Sibling, string Side);

internal sealed record SignedRoot(
    string Root,
    string? PrevRoot,
    long LeafCount,
    string Signature,
    string PublicKey);

internal sealed record ChunkResult(string ChunkId, bool HashOk, bool InclusionOk);

internal sealed record VerificationResult(bool Verified, bool SignatureOk, List<ChunkResult> Chunks);
