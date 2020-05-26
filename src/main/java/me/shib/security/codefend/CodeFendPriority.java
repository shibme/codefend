package me.shib.security.codefend;

public enum CodeFendPriority {
    P0(0), P1(1), P2(2), P3(3), P4(4);

    private final int rank;

    CodeFendPriority(int rank) {
        this.rank = rank;
    }

    public int getRank() {
        return rank;
    }
}
