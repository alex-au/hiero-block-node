// SPDX-License-Identifier: Apache-2.0
package org.hiero.block.common.hasher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.hedera.hapi.node.base.Timestamp;
import com.hedera.pbj.runtime.io.buffer.Bytes;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/// Tests for the [HashingUtilities] class, focused on the extension subtree aware final block
/// hash computation. Expected values are produced by a local reference implementation of the
/// HIP-1424 block root tree ("Merkle Mountain Top"), independent of the production code, so the
/// two implementations must agree.
@DisplayName("Hashing Utilities Tests")
class HashingUtilitiesTest {
    private static final int HASH_SIZE = 48;
    /// Deterministic seed so failures are reproducible.
    private static final Random RANDOM = new Random(6431582L);

    /// Tests for [HashingUtilities#computeFinalBlockHash] with extension subtree roots.
    @Nested
    @DisplayName("Final Block Hash Extension Subtree Tests")
    class FinalBlockHashExtensionSubtreeTests {
        /// This test aims to assert that the legacy overload without extension subtree roots
        /// produces the exact same hash as the extension aware overload with no extension
        /// subtree present, which is also the historical 8 leaf computation.
        @Test
        @DisplayName("computeFinalBlockHash() no extensions matches legacy overload")
        void testNoExtensionsMatchesLegacyOverload() {
            final FixedTreeInputs inputs = randomInputs();
            final Bytes legacy = HashingUtilities.computeFinalBlockHash(
                    inputs.timestamp(),
                    inputs.previousBlockHash(),
                    inputs.rootOfAllPreviousBlockHashes(),
                    inputs.startOfBlockStateRootHash(),
                    inputs.inputTreeHasher(),
                    inputs.outputTreeHasher(),
                    inputs.consensusHeaderHasher(),
                    inputs.stateChangesHasher(),
                    inputs.traceDataHasher());
            final Bytes extensionAware = HashingUtilities.computeFinalBlockHash(
                    inputs.timestamp(),
                    inputs.previousBlockHash(),
                    inputs.rootOfAllPreviousBlockHashes(),
                    inputs.startOfBlockStateRootHash(),
                    inputs.inputTreeHasher(),
                    inputs.outputTreeHasher(),
                    inputs.consensusHeaderHasher(),
                    inputs.stateChangesHasher(),
                    inputs.traceDataHasher(),
                    new byte[HashingUtilities.EXTENSION_SUBTREE_COUNT][]);
            assertThat(extensionAware).isEqualTo(legacy);
            assertThat(extensionAware).isEqualTo(referenceRootHash(inputs, new byte[8][]));
        }

        /// This test aims to assert that every presence pattern of the eight extension
        /// subtree leaves produces the block root hash computed by the reference
        /// implementation of the HIP-1424 tree. Patterns are supplied as bitmasks where bit N
        /// marks Extension N as present.
        @ParameterizedTest
        @ValueSource(ints = {0b00000001, 0b00000010, 0b10000000, 0b00001001, 0b01100110, 0b11111111})
        @DisplayName("computeFinalBlockHash() extension presence patterns match reference")
        void testExtensionPresencePatternsMatchReference(final int presenceMask) {
            final FixedTreeInputs inputs = randomInputs();
            final byte[][] extensionRoots = new byte[HashingUtilities.EXTENSION_SUBTREE_COUNT][];
            for (int i = 0; i < extensionRoots.length; i++) {
                if ((presenceMask & (1 << i)) != 0) {
                    extensionRoots[i] = randomHash();
                }
            }
            final Bytes actual = HashingUtilities.computeFinalBlockHash(
                    inputs.timestamp(),
                    inputs.previousBlockHash(),
                    inputs.rootOfAllPreviousBlockHashes(),
                    inputs.startOfBlockStateRootHash(),
                    inputs.inputTreeHasher(),
                    inputs.outputTreeHasher(),
                    inputs.consensusHeaderHasher(),
                    inputs.stateChangesHasher(),
                    inputs.traceDataHasher(),
                    extensionRoots);
            assertThat(actual).isEqualTo(referenceRootHash(inputs, extensionRoots));
        }

        /// This test aims to assert that a presence pattern with extension items produces a
        /// different root hash than the same inputs with no extension items, so extension
        /// items can never be dropped without changing the block hash.
        @Test
        @DisplayName("computeFinalBlockHash() extension presence changes the root hash")
        void testExtensionPresenceChangesRootHash() {
            final FixedTreeInputs inputs = randomInputs();
            final byte[][] noExtensions = new byte[HashingUtilities.EXTENSION_SUBTREE_COUNT][];
            final byte[][] withExtension = new byte[HashingUtilities.EXTENSION_SUBTREE_COUNT][];
            withExtension[0] = randomHash();
            final Bytes without = HashingUtilities.computeFinalBlockHash(
                    inputs.timestamp(),
                    inputs.previousBlockHash(),
                    inputs.rootOfAllPreviousBlockHashes(),
                    inputs.startOfBlockStateRootHash(),
                    inputs.inputTreeHasher(),
                    inputs.outputTreeHasher(),
                    inputs.consensusHeaderHasher(),
                    inputs.stateChangesHasher(),
                    inputs.traceDataHasher(),
                    noExtensions);
            final Bytes with = HashingUtilities.computeFinalBlockHash(
                    inputs.timestamp(),
                    inputs.previousBlockHash(),
                    inputs.rootOfAllPreviousBlockHashes(),
                    inputs.startOfBlockStateRootHash(),
                    inputs.inputTreeHasher(),
                    inputs.outputTreeHasher(),
                    inputs.consensusHeaderHasher(),
                    inputs.stateChangesHasher(),
                    inputs.traceDataHasher(),
                    extensionRoots());
            assertThat(with).isNotEqualTo(without);
        }

        private byte[][] extensionRoots() {
            final byte[][] roots = new byte[HashingUtilities.EXTENSION_SUBTREE_COUNT][];
            roots[0] = randomHash();
            return roots;
        }

        /// This test aims to assert that an extension subtree roots array of the wrong length
        /// is rejected.
        @ParameterizedTest
        @ValueSource(ints = {0, 7, 9})
        @DisplayName("computeFinalBlockHash() wrong extension root count throws")
        void testWrongExtensionRootCountThrows(final int count) {
            final FixedTreeInputs inputs = randomInputs();
            assertThatThrownBy(() -> HashingUtilities.computeFinalBlockHash(
                            inputs.timestamp(),
                            inputs.previousBlockHash(),
                            inputs.rootOfAllPreviousBlockHashes(),
                            inputs.startOfBlockStateRootHash(),
                            inputs.inputTreeHasher(),
                            inputs.outputTreeHasher(),
                            inputs.consensusHeaderHasher(),
                            inputs.stateChangesHasher(),
                            inputs.traceDataHasher(),
                            new byte[count][]))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    /// The inputs to a final block hash computation.
    private record FixedTreeInputs(
            Timestamp timestamp,
            Bytes previousBlockHash,
            Bytes rootOfAllPreviousBlockHashes,
            Bytes startOfBlockStateRootHash,
            StreamingTreeHasher inputTreeHasher,
            StreamingTreeHasher outputTreeHasher,
            StreamingTreeHasher consensusHeaderHasher,
            StreamingTreeHasher stateChangesHasher,
            StreamingTreeHasher traceDataHasher) {}

    /// Builds deterministic pseudo random inputs: the block level values and the five category
    /// subtree hashers with varying leaf counts, including an empty one.
    private static FixedTreeInputs randomInputs() {
        return new FixedTreeInputs(
                new Timestamp(RANDOM.nextLong(0, Long.MAX_VALUE), RANDOM.nextInt(0, 1_000_000_000)),
                Bytes.wrap(randomHash()),
                Bytes.wrap(randomHash()),
                Bytes.wrap(randomHash()),
                hasherWithLeaves(1),
                hasherWithLeaves(3),
                hasherWithLeaves(0),
                hasherWithLeaves(4),
                hasherWithLeaves(2));
    }

    private static StreamingTreeHasher hasherWithLeaves(final int leafCount) {
        final NaiveStreamingTreeHasher hasher = new NaiveStreamingTreeHasher();
        for (int i = 0; i < leafCount; i++) {
            hasher.addLeaf(ByteBuffer.wrap(randomHash()));
        }
        return hasher;
    }

    private static byte[] randomHash() {
        final byte[] hash = new byte[HASH_SIZE];
        RANDOM.nextBytes(hash);
        return hash;
    }

    /// Reference implementation of the block root hash per HIP-1424: a fixed 16 leaf tree whose
    /// left half holds the eight assigned leaves and whose right half holds the extension
    /// subtrees, with absent leaves excluded and single child nodes prefixed with 0x01. The
    /// root combines the consensus timestamp leaf with the tree.
    private static Bytes referenceRootHash(final FixedTreeInputs inputs, final byte[][] extensionRoots) {
        final byte[] consensusRoot =
                inputs.consensusHeaderHasher().rootHash().join().toByteArray();
        final byte[] inputsRoot = inputs.inputTreeHasher().rootHash().join().toByteArray();
        final byte[] outputsRoot = inputs.outputTreeHasher().rootHash().join().toByteArray();
        final byte[] stateChangesRoot =
                inputs.stateChangesHasher().rootHash().join().toByteArray();
        final byte[] traceRoot = inputs.traceDataHasher().rootHash().join().toByteArray();
        final byte[] leftHalf = refNode(
                refNode(
                        refNode(
                                inputs.previousBlockHash().toByteArray(),
                                inputs.rootOfAllPreviousBlockHashes().toByteArray()),
                        refNode(inputs.startOfBlockStateRootHash().toByteArray(), consensusRoot)),
                refNode(refNode(inputsRoot, outputsRoot), refNode(stateChangesRoot, traceRoot)));
        final byte[] rightHalf = refCombineOptional(
                refCombineOptional(
                        refCombineOptional(extensionRoots[0], extensionRoots[1]),
                        refCombineOptional(extensionRoots[2], extensionRoots[3])),
                refCombineOptional(
                        refCombineOptional(extensionRoots[4], extensionRoots[5]),
                        refCombineOptional(extensionRoots[6], extensionRoots[7])));
        final byte[] mountainTop = rightHalf == null ? refSingle(leftHalf) : refNode(leftHalf, rightHalf);
        final byte[] timestampLeaf =
                refLeaf(Timestamp.PROTOBUF.toBytes(inputs.timestamp()).toByteArray());
        return Bytes.wrap(refNode(timestampLeaf, mountainTop));
    }

    private static byte[] refCombineOptional(final byte[] left, final byte[] right) {
        final byte[] node;
        if (left == null && right == null) {
            node = null;
        } else if (left == null) {
            node = refSingle(right);
        } else if (right == null) {
            node = refSingle(left);
        } else {
            node = refNode(left, right);
        }
        return node;
    }

    private static byte[] refLeaf(final byte[] data) {
        return refSha384(new byte[] {0x00}, data);
    }

    private static byte[] refSingle(final byte[] child) {
        return refSha384(new byte[] {0x01}, child);
    }

    private static byte[] refNode(final byte[] left, final byte[] right) {
        return refSha384(new byte[] {0x02}, left, right);
    }

    private static byte[] refSha384(final byte[]... parts) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-384");
            for (final byte[] part : parts) {
                digest.update(part);
            }
            return digest.digest();
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
