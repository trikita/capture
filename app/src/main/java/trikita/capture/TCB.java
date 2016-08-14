package trikita.capture;

import android.util.Pair;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

public class TCB {

    private long mSeqLocal;
    private long mSeqRemote;
    private long mAckLocal;
    private long mAckRemote;

    private TCBStatus mStatus;
    private Pair<InetSocketAddress, InetSocketAddress> uniqueKey;

    public void setUniqueKey(Pair<InetSocketAddress, InetSocketAddress> uniqueKey) {
        this.uniqueKey = uniqueKey;
    }

    public Pair<InetSocketAddress, InetSocketAddress> getUniqueKey() {
        return uniqueKey;
    }

    public long getAckRemote() {
        return mAckRemote;
    }

    public void setAckRemote(long mAckRemote) {
        this.mAckRemote = mAckRemote;
    }

    public long getAckLocal() {
        return mAckLocal;
    }

    public void setAckLocal(long mAckLocal) {
        this.mAckLocal = mAckLocal;
    }

    public long getSeqLocal() {
        return mSeqLocal;
    }

    public void setSeqLocal(long mSeqLocal) {
        this.mSeqLocal = mSeqLocal;
    }

    public long getSeqRemote() {
        return mSeqRemote;
    }

    public void setSeqRemote(long mSeqRemote) {
        this.mSeqRemote = mSeqRemote;
    }

    // TCP has more states, but we need only these
    public enum TCBStatus {
        SYN_SENT,
        SYN_RECEIVED,
        ESTABLISHED,
        CLOSE_WAIT,
        LAST_ACK,
    }

    private SocketChannel mSocket;
    private SelectionKey mSelectionKey;

    public TCB(long seqLocal, long seqRemote, long ackLocal, long ackRemote, SocketChannel s) {
        mSeqLocal = seqLocal;
        mSeqRemote = seqRemote;
        mAckLocal = ackLocal;
        mAckRemote = ackRemote;

        mSocket = s;
    }

    public TCBStatus getStatus() { return mStatus; }
    public SocketChannel getSocket() { return mSocket; }
    public SelectionKey getSelectionKey() { return mSelectionKey; }

    public void setStatus(TCBStatus status) { this.mStatus = status; }
    public void setSocket(SocketChannel socket) { this.mSocket = socket; }
    public void setSelectionKey(SelectionKey selectionKey) { this.mSelectionKey = selectionKey; }

    public void closeSocket() {
        try { mSocket.close(); } catch (IOException e) {}
    }
}

