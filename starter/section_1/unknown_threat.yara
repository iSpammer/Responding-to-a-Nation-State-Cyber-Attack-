rule crypto_miner {
        meta:
                Author = "@ispaam"
                Description = "the rule detects the presence of miners installation script"
        strings:
                $miner = "miner"
		$mine = "mine"
                $darklord = "darkl0rd"
                $ssht = "SSH-T"
                $sshone = "SSH-One"
                $stratum = "stratum"
                $wallet = "WALLET"
                $ppx = "ppx"
                $xmr = "xmr"
                $ppxxmr = "ppxxmr"
                $wallet = "hfs_m"
                $wallet = "hfs_s"
                $cryptonight = "cryptonight"
                $wallet = "WALLET"
                $download = "Downloading XMR Miner"
        condition:
                any of them

}
