# CTW Social Club Revival

Restores the **Social Club entitlement** in *GTA: Chinatown Wars* (DS) that died with Rockstar's
service, unlocks the following:
- Xin Shan missions
- Promo vehicles
  - Bulletproof Patriot
  - Bulletproof Infernus
  - Bulletproof Hellenbach
  - Bulletproof Cavalcade FXT
- Sean (81st dealer)
- $10,000 (Ammu-Nation reward)

on an unmodified console and an unmodified save. No ROM patches, no save editing.

The original prerequisites are enforced: Xin Shan needs the story finished **and** both Lions of Fo
collected, Sean needs all 100 security cameras destroyed. A save that has not got there yet is served
nothing, the way Rockstar's backend would have. Pass `--progress-gate off --sean-gate off` to hand
everything out unconditionally.

## Quick start

```bash
python3 test_entitlement.py            # 91 checks, no dependencies
sudo python3 ctw_selfhost.py --help    # needs root: binds 53, 80, 443
```

Then on the DS, in the game's own WFC settings: set **Auto-obtain DNS** to **No**, and both primary and
secondary DNS to the address the script prints. Start the game and use its online option, the console
writes its own save when the grant lands.

## Porting

Adding this to an existing WFC server? The bit map, the save fields and the gate are in
[WIILINK-NOTES.md](WIILINK-NOTES.md).

## Credits

- [WiiLink WFC](https://github.com/WiiLink24/wfc-server)
- [nds-constraint](https://github.com/KaeruTeam/nds-constraint)
- [dwc_network_server_emulator](https://github.com/barronwaffles/dwc_network_server_emulator)

GTA: Chinatown Wars is © Rockstar Games. Unaffiliated with Rockstar, Nintendo or GameSpy. Ships no game
code or assets and modifies nothing on the player's console or save.
