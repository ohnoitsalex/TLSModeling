package org.bouncycastle.tls;

/**
 * RFC 4347 4.1.2.5 Anti-replay
 * <p>
 * Support fast rejection of duplicate records by maintaining a sliding receive window
 * </p>
 */
class DTLSReplayWindow
{
    private static final long VALID_SEQ_MASK = 0x0000FFFFFFFFFFFFL;

    private static final long WINDOW_SIZE = 64L;

    private long latestConfirmedSeq = -1;
    private long bitmap = 0;

    /**
     * Check whether a received record with the given sequence number should be rejected as a duplicate.
     *
     * @param seq the 48-bit DTLSPlainText.sequence_number field of a received record.
     * @return true if the record should be discarded without further processing.
     */
    boolean shouldDiscard(long seq)
    {
        if ((seq & VALID_SEQ_MASK) != seq)
        {
            return true;
        }

        if (seq <= latestConfirmedSeq)
        {
            long diff = latestConfirmedSeq - seq;
            if (diff >= WINDOW_SIZE)
            {
                return true;
            }
            return (bitmap & (1L << diff)) != 0;
        }

        return false;
    }

    /**
     * Report that a received record with the given sequence number passed authentication checks.
     *
     * @param seq the 48-bit DTLSPlainText.sequence_number field of an authenticated record.
     */
    boolean reportAuthenticated(long seq)
    {
        if ((seq & VALID_SEQ_MASK) != seq)
        {
            throw new IllegalArgumentException("'seq' out of range");
        }

        if (seq <= latestConfirmedSeq)
        {
            long diff = latestConfirmedSeq - seq;
            if (diff < WINDOW_SIZE)
            {
                bitmap |= (1L << diff);
            }
            return false;
        }
        else
        {
            long diff = seq - latestConfirmedSeq;
            if (diff >= WINDOW_SIZE)
            {
                bitmap = 1;
            }
            else
            {
                bitmap <<= (int)diff;        // for earlier JDKs
                bitmap |= 1;
            }
            latestConfirmedSeq = seq;
            return true;
        }
    }

    void reset(long seq)
    {
        if ((seq & VALID_SEQ_MASK) != seq)
        {
            throw new IllegalArgumentException("'seq' out of range");
        }

        // Discard future records unless sequence number > 'seq'
        latestConfirmedSeq = seq;
        bitmap = -1L >>> Math.max(0, 63 - seq);
    }
}
