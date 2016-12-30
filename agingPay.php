<?php 
header("Content-type: text/html; charset=utf-8"); 
$url = 'http://xxxxxx/pay/index';

$signStrMain = array
(
    'transcode' => '8001',
    'oid_partner' => '201603290000000000',
    'version' => '1.0',
    'user_id' => '336',
    'mob_user' => '15900000000',
);

$signStr = json_encode($signStrMain);
 
$content = rsaSign::rsaEncrypt($signStr, './trader_public_key.pem');//加密，此处文件为有贝的公钥

$sign = rsaSign::sign($signStr, './trader_private_key.pem');//签名，此处文件商户私钥


/**
 * Created by PhpStorm.
* User: Bruin
* Date: 2016/9/28
* Time: 19:23
*/

class rsaSign{

    /*
     * openssl扩展支持
     */
    public function __construct()
    {
        extension_loaded('openssl') or die('php需要openssl扩展支持');
    }

    /**
     * 加签
     * @param $data 要加签的数据
     * @param $privateKeyFilePath 私钥文件路径
     * @return string 签名
     */
    public static function sign($data, $privateKeyFilePath) {
        $priKey = file_get_contents($privateKeyFilePath);
        $res = openssl_get_privatekey($priKey);
        openssl_sign($data, $sign, $res, OPENSSL_ALGO_SHA1);
        openssl_free_key($res);
        $sign = base64_encode($sign);
        return $sign;
    }

    /**
     * 验签
     * @param $data 用来加签的数据
     * @param $sign 加签后的结果
     * @param $rsaPublicKeyFilePath 公钥文件路径
     * @return bool 验签是否成功
     */
    public static function verify($data, $sign, $rsaPublicKeyFilePath) {
        //读取公钥文件
        $pubKey = file_get_contents($rsaPublicKeyFilePath);

        //转换为openssl格式密钥
        $res = openssl_get_publickey($pubKey);

        //调用openssl内置方法验签，返回bool值
        $result = (bool)openssl_verify($data, base64_decode($sign), $res);

        //释放资源
        openssl_free_key($res);

        return $result;
    }


    /**
     * rsa加密
     * @param $data 要加密的数据
     * @param $pubKeyFilePath 公钥文件路径
     * @return string 加密后的密文
     */
    public static function rsaEncrypt($data, $pubKeyFilePath){
        //读取公钥文件
        $pubKey = file_get_contents($pubKeyFilePath);
        //转换为openssl格式密钥
        $res = openssl_get_publickey($pubKey);

        $maxlength = rsaSign::getMaxEncryptBlockSize($res);
        $output='';
        $split = str_split($data , $maxlength);
        foreach($split as $part){
            openssl_public_encrypt($part,$encrypted,$pubKey);
            $output.= $encrypted;
        }
        $encryptedData =  base64_encode($output);
        return $encryptedData;
    }

    /**
     * 解密
     * @param $data 要解密的数据
     * @param $privateKeyFilePath 私钥文件路径
     * @return string 解密后的明文
     */
    public static function rsaDecrypt($data, $privateKeyFilePath){
        //读取私钥文件
        $priKey = file_get_contents($privateKeyFilePath);
        //转换为openssl格式密钥
        $res = openssl_get_privatekey($priKey);
        $data = base64_decode($data);
        $maxlength = rsaSign::getMaxDecryptBlockSize($res);
        $output='';
        $split = str_split($data , $maxlength);
        foreach($split as $part){
            openssl_private_decrypt($part,$encrypted,$pubKey);
            $output.= $encrypted;
        }
        return $output;
    }

    /**
     *根据key的内容获取最大加密lock的大小，兼容各种长度的rsa keysize（比如1024,2048）
     * 对于1024长度的RSA Key，返回值为117
     * @param $keyRes
     * @return float
     */
    public static function getMaxEncryptBlockSize($keyRes){
        $keyDetail = openssl_pkey_get_details($keyRes);
        $modulusSize = $keyDetail['bits'];
        return $modulusSize/8 - 11;
    }

    /**
     * 根据key的内容获取最大解密block的大小，兼容各种长度的rsa keysize（比如1024,2048）
     * 对于1024长度的RSA Key，返回值为128
     * @param $keyRes
     * @return float
     */
    public static function getMaxDecryptBlockSize($keyRes){
        $keyDetail = openssl_pkey_get_details($keyRes);
        $modulusSize = $keyDetail['bits'];
        return $modulusSize/8;
    }
}


?>


<html>
<body>
<form method="post"  action="<?php echo $url;?>">
<input type="hidden" name="content" value=<?php echo $content ;?>/>
<input type="hidden" name="sign" value=<?php echo $sign ;?> />
<?php 
foreach ($signStrMain  as $k=>$v) {?>
    <input type="hidden"  name="<?php echo $k;?>" value="<?php echo $v?>"/>
<?php }
?>

<input type="submit" name='submit' value='submit'/>

</form>
</body>


</html>