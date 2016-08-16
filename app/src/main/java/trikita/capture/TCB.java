package trikita.capture;

import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

public class TCB {

    public static final int SYN_SENT = 0;
    public static final int SYN_RECEIVED = 1;
    public static final int ESTABLISHED = 2;
    public static final int CLOSE_WAIT = 3;
    public static final int LAST_ACK = 4;
    public static final int CLOSE_WAIT_2 = 5;

    private final IPUtils.SocketID mID;
    private final SocketChannel mSocket;
    private int mLocalSeq;
    private int mLocalAck;
    private int mRemoteSeq;
    private int mRemoteAck;

    private int mStatus = SYN_SENT;
    private SelectionKey mSelectionKey;

    public TCB(IPUtils.SocketID id, SocketChannel socket, int localSeq, int remoteSeq, int localAck, int remoteAck) {
        mID = id;
        mSocket = socket;
        mLocalSeq = localSeq;
        mLocalAck = localAck;
        mRemoteSeq = remoteSeq;
        mRemoteAck = remoteAck;
    }

    public int getRemoteAck() { return mRemoteAck; }
    public int getRemoteSeq() { return mRemoteSeq; }
    public int getLocalAck() { return mLocalAck; }
    public int getLocalSeq() { return mLocalSeq; }
    public int getStatus() { return mStatus; }
    public IPUtils.SocketID getID() { return mID; }
    public SocketChannel getSocket() { return mSocket; }

    public void closeSocket() {
        if (mSocket != null) {
            try {
                System.out.println("really, close socket");
                mSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void advanceSeq(int n) {
        mLocalSeq += n;
    }

    // TODO: do we nede it?
    public void setSelectionKey(SelectionKey selectionKey) {
        mSelectionKey = selectionKey;
    }

    public void setStatus(int status) {
        mStatus = status;
    }

    public void setLocalAck(int ack) {
        mLocalAck = ack;
    }

    public void setRemoteAck(int ack) {
        mRemoteAck = ack;
    }
}

