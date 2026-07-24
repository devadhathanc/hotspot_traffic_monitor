package com.hotspotd.usage;

import java.time.Duration;

public class Usage {
    private final long download;
    private final long upload;
    private final Duration duration;

    public Usage(long download, long upload, Duration duration) {
        this.download = download;
        this.upload = upload;
        this.duration = duration;
    }

    public long getDownload() {
        return download;
    }

    public long getUpload() {
        return upload;
    }

    public Duration getDuration() {
        return duration;
    }
}
