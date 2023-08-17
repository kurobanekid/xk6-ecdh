import ecdh from 'k6/x/ecdh'

export default function () {
    const clientMaterial = {};
    clientMaterial.d = "df552da58b3b2a60e17bc1c2b5daeed2430d9c95205c990ac75090cb8d7a8cbf"
    clientMaterial.pubX = "ae69a23174b857952d61ca2b4b45ca3c07c80884f936c098c85cb0641112ba93"
    clientMaterial.pubY = "37e732009ba5ff20846b0c2d09f0c039ed800d1243010e8cf5657dd5459ba7e4"
    clientMaterial.srvPubX = "42fd184a6aff823c008014d7f2f2690812deb575b7710bd1046859488b58df8d"
    clientMaterial.srvPubY = "fef047597f72af36ad7f87ac98b6107e367f94e11fbb6c016bfd86b6fb8758bd"

    const output = ecdh.computeSharedSecret(JSON.stringify(clientMaterial))
    console.log(output)
}