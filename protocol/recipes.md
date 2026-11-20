# Roc Recipes for Testing

These commands allow testing host and phone audio streams independently using `roc-toolkit`.

## Host without a phone (receive on loopback)

Run `roc-recv` on loopback to listen to the host's outgoing Roc stream:

```sh
roc-recv -vv -s rtp+rs8m://0.0.0.0:10001 -r rs8m://0.0.0.0:10002 -o file:out.wav
```

## Phone without a host (send a file to the phone)

Send an audio file from the host directly to the phone's Roc receiver:

```sh
roc-send -vv -s rtp+rs8m://<phone-ip>:<p1> -r rs8m://<phone-ip>:<p2> -i file:test.wav
```
