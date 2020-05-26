/*
 *       Copyright© (2019) WeBank Co., Ltd.
 *
 *       This file is part of weidentity-sample.
 *
 *       weidentity-sample is free software: you can redistribute it and/or modify
 *       it under the terms of the GNU Lesser General Public License as published by
 *       the Free Software Foundation, either version 3 of the License, or
 *       (at your option) any later version.
 *
 *       weidentity-sample is distributed in the hope that it will be useful,
 *       but WITHOUT ANY WARRANTY; without even the implied warranty of
 *       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *       GNU Lesser General Public License for more details.
 *
 *       You should have received a copy of the GNU Lesser General Public License
 *       along with weidentity-sample.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.webank.weid.demo.service.impl;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.demo.common.util.FileUtil;
import com.webank.weid.demo.common.util.PrivateKeyUtil;
import com.webank.weid.demo.service.DemoService;
import com.webank.weid.protocol.base.AuthorityIssuer;
import com.webank.weid.protocol.base.CptBaseInfo;
import com.webank.weid.protocol.base.Credential;
import com.webank.weid.protocol.base.CredentialWrapper;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.request.CptMapArgs;
import com.webank.weid.protocol.request.CreateCredentialArgs;
import com.webank.weid.protocol.request.CreateWeIdArgs;
import com.webank.weid.protocol.request.RegisterAuthorityIssuerArgs;
import com.webank.weid.protocol.request.SetAuthenticationArgs;
import com.webank.weid.protocol.request.SetPublicKeyArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.rpc.AuthorityIssuerService;
import com.webank.weid.rpc.CptService;
import com.webank.weid.rpc.CredentialService;
import com.webank.weid.rpc.WeIdService;
import com.webank.weid.service.impl.AuthorityIssuerServiceImpl;
import com.webank.weid.service.impl.CptServiceImpl;
import com.webank.weid.service.impl.CredentialServiceImpl;
import com.webank.weid.service.impl.WeIdServiceImpl;
import com.webank.weid.util.DataToolUtils;

/**
 * Demo service.
 *
 * @author v_wbgyang
 */
@Service
public class DemoServiceImpl implements DemoService {

    private static final Logger logger = LoggerFactory.getLogger(DemoServiceImpl.class);

    private AuthorityIssuerService authorityIssuerService = new AuthorityIssuerServiceImpl();

    private CptService cptService = new CptServiceImpl();

    private CredentialService credentialService = new CredentialServiceImpl();

    private WeIdService weIdService = new WeIdServiceImpl();

    /**
     * set validity period to 360 days by default.
     */
    private static final long EXPIRATION_DATE  = 1000L * 60 * 60 * 24 * 365 * 100;


    /**
     * create weId with public and private keys and set related properties.
     * 
     * @param publicKey public key
     * @param privateKey private key
     * @return returns the create weId
     */
    public ResponseData<String> createWeIdAndSetAttr(String publicKey, String privateKey) {

        logger.info("begin create weId and set attribute without parameter");

        // 1, create weId using the incoming public and private keys
        CreateWeIdArgs createWeIdArgs = new CreateWeIdArgs();
        createWeIdArgs.setPublicKey(publicKey);
        createWeIdArgs.setWeIdPrivateKey(new WeIdPrivateKey());
        createWeIdArgs.getWeIdPrivateKey().setPrivateKey(privateKey);
        ResponseData<String> createResult = weIdService.createWeId(createWeIdArgs);
        logger.info("createWeIdAndSetAttr response:{}", createResult);
        if (createResult.getErrorCode().intValue() != ErrorCode.SUCCESS.getCode()) {
            return createResult;
        }

        // todo  将 私钥 和 注册DID的结果存储到本地指定文件中
        PrivateKeyUtil.savePrivateKey(
            PrivateKeyUtil.KEY_DIR,
            createResult.getResult(), // 这里面是 weId
            privateKey
        );

        /*CreateWeIdDataResult weIdData = new CreateWeIdDataResult();
        weIdData.setWeId(createResult.getResult());
        weIdData.setUserWeIdPrivateKey(new WeIdPrivateKey());
        weIdData.getUserWeIdPrivateKey().setPrivateKey(privateKey);
        weIdData.setUserWeIdPublicKey(new WeIdPublicKey());
        weIdData.getUserWeIdPublicKey().setPublicKey(publicKey);

        // 2, call set public key
        ResponseData<Boolean> setPublicKeyRes = this.setPublicKey(weIdData);
        if (!setPublicKeyRes.getResult()) {
            createResult.setErrorCode(
                ErrorCode.getTypeByErrorCode(setPublicKeyRes.getErrorCode())
            );
            return createResult;
        }

        // 3, call set authentication
        ResponseData<Boolean> setAuthenticateRes = this.setAuthentication(weIdData);
        if (!setAuthenticateRes.getResult()) {
            createResult.setErrorCode(
                ErrorCode.getTypeByErrorCode(setAuthenticateRes.getErrorCode())
            );
            return createResult;
        }*/
        return createResult;
    }


    /**
    *
    *  权威发行者   委员会   和 UseAgent 都调用了这里 注册对应的 WeId
    *  并将 PriKey 存储在本地
     * 创建weid.
     * @return
     */
    public ResponseData<CreateWeIdDataResult> createWeId() {


        // todo 这里将 WeId 存储在chain
        ResponseData<CreateWeIdDataResult> response = createWeIdWithSetAttr();
        // if weId is created successfully, save its private key.
        //
        // 如果将 WeId 存储到 chain 成功, 则我们需要在本地文件保存 priKey
        if (response.getErrorCode().intValue() == ErrorCode.SUCCESS.getCode()) {

            // 在本地 文件 保存 priKey
            PrivateKeyUtil.savePrivateKey(
                PrivateKeyUtil.KEY_DIR,
                response.getResult().getWeId(),
                response.getResult().getUserWeIdPrivateKey().getPrivateKey()
            );
        }

        /*
         *  private keys are not allowed to be transmitted over http, so this place
         *  annotates the return of private keys to avoid misuse.
         */
        // priKey 不对 Http 接口外部返回
        response.getResult().setUserWeIdPrivateKey(null);
        return response;
    }

    /**
    * 注册 WeId 并 设置 Document 中某些关联字段
    *
     * create weId and set related properties.
     * 
     * @return returns the create weId and public private keys
     */
    private ResponseData<CreateWeIdDataResult> createWeIdWithSetAttr() {

        logger.info("begin create weId and set attribute");

        // 1, create weId, this method automatically creates public and private keys
        //
        // 使用本地的公私钥对, 创建 weId 并存储在chain
        ResponseData<CreateWeIdDataResult> createResult = weIdService.createWeId();
        logger.info(
            "weIdService is result,errorCode:{},errorMessage:{}",
            createResult.getErrorCode(), createResult.getErrorMessage()
        );

        if (createResult.getErrorCode().intValue() != ErrorCode.SUCCESS.getCode()) {
            return createResult;
        }

        // 2, call set public key
        //
        // 将 pubKey 存到chain
        ResponseData<Boolean> setPublicKeyRes = this.setPublicKey(createResult.getResult());
        if (!setPublicKeyRes.getResult()) {
            createResult.setErrorCode(
                ErrorCode.getTypeByErrorCode(setPublicKeyRes.getErrorCode())
            );
            return createResult;
        }

        // 3, call set authentication
        //
        // 将 认证方式 存到chain
        ResponseData<Boolean> setAuthenticateRes = this.setAuthentication(createResult.getResult());
        if (!setAuthenticateRes.getResult()) {
            createResult.setErrorCode(
                ErrorCode.getTypeByErrorCode(setAuthenticateRes.getErrorCode())
            );
            return createResult;
        }
        return createResult;
    }

    /**
    *  TODO 注意这里操作 DID的 Document
     * Set Public Key For WeIdentity DID Document.
     *
     * @param createWeIdDataResult the object of CreateWeIdDataResult
     * @return the response data
     */
    private ResponseData<Boolean> setPublicKey(CreateWeIdDataResult createWeIdDataResult) {

        // build setPublicKey parameters.
        //
        // 构建 publicKey 参数
        SetPublicKeyArgs setPublicKeyArgs = new SetPublicKeyArgs();
        setPublicKeyArgs.setWeId(createWeIdDataResult.getWeId());
        setPublicKeyArgs.setPublicKey(createWeIdDataResult.getUserWeIdPublicKey().getPublicKey());
        setPublicKeyArgs.setUserWeIdPrivateKey(new WeIdPrivateKey());
        setPublicKeyArgs.getUserWeIdPrivateKey()
            .setPrivateKey(createWeIdDataResult.getUserWeIdPrivateKey().getPrivateKey());

        // call SDK method to chain set attribute.
        //
        //
        ResponseData<Boolean> setResponse = weIdService.setPublicKey(setPublicKeyArgs);
        logger.info(
            "setPublicKey is result,errorCode:{},errorMessage:{}",
            setResponse.getErrorCode(), 
            setResponse.getErrorMessage()
        );
        return setResponse;
    }

    /**
    *  TODO 注意这里操作 DID的 Document
     * Set Authentication For WeIdentity DID Document.
     *
     * @param createWeIdDataResult createWeIdDataResult the object of CreateWeIdDataResult
     * @return the response data
     */
    private ResponseData<Boolean> setAuthentication(CreateWeIdDataResult createWeIdDataResult) {

        // build setAuthentication parameters.
        //
        // 组装 认证方式 参数
        SetAuthenticationArgs setAuthenticationArgs = new SetAuthenticationArgs();
        setAuthenticationArgs.setWeId(createWeIdDataResult.getWeId());
        setAuthenticationArgs
            .setPublicKey(createWeIdDataResult.getUserWeIdPublicKey().getPublicKey());
        setAuthenticationArgs.setUserWeIdPrivateKey(new WeIdPrivateKey());
        setAuthenticationArgs.getUserWeIdPrivateKey()
            .setPrivateKey(createWeIdDataResult.getUserWeIdPrivateKey().getPrivateKey());

        // call SDK method to chain set attribute.
        ResponseData<Boolean> setResponse = weIdService.setAuthentication(setAuthenticationArgs);
        logger.info(
            "setAuthentication is result,errorCode:{},errorMessage:{}",
            setResponse.getErrorCode(), 
            setResponse.getErrorMessage()
        );
        return setResponse;
    }

    /**
    * 注册一个 权威发行者
     * register on the chain as an authoritative body.
     * 
     * @param authorityName the name of the issue
     * @return true is success, false is failure
     */
    @Override
    public ResponseData<Boolean> registerAuthorityIssuer(String issuer, String authorityName) {

        // build registerAuthorityIssuer parameters.
        AuthorityIssuer authorityIssuerResult = new AuthorityIssuer();
        authorityIssuerResult.setWeId(issuer);  // 权威发行者的 weId
        authorityIssuerResult.setName(authorityName); // 权威发行者的名称
        authorityIssuerResult.setAccValue("0"); // todo 这个是啥 ??

        RegisterAuthorityIssuerArgs registerAuthorityIssuerArgs = new RegisterAuthorityIssuerArgs();
        registerAuthorityIssuerArgs.setAuthorityIssuer(authorityIssuerResult);
        registerAuthorityIssuerArgs.setWeIdPrivateKey(new WeIdPrivateKey());

        // getting SDK private key from file.
        //
        // 加载 自己的 priKey
        String privKey = FileUtil.getDataByPath(PrivateKeyUtil.SDK_PRIVKEY_PATH);

        registerAuthorityIssuerArgs.getWeIdPrivateKey().setPrivateKey(privKey);

        ResponseData<Boolean> registResponse =
            authorityIssuerService.registerAuthorityIssuer(registerAuthorityIssuerArgs);
        logger.info(
            "registerAuthorityIssuer is result,errorCode:{},errorMessage:{}",
            registResponse.getErrorCode(), 
            registResponse.getErrorMessage()
        );
        return registResponse;
    }

    /**
    * 往 chain 上注册 CPT 模板信息
     * registered CPT.
     * 
     * @param publisher the weId of the publisher
     * @param privateKey the private key of the publisher
     * @param claim claim is CPT
     * @return returns cptBaseInfo
     */
    @Override
    public ResponseData<CptBaseInfo> registCpt(
        String publisher, 
        String privateKey, 
        Map<String, Object> claim) {

        // build registerCpt parameters.
        //
        // 构建 注册CPT模板 参数
        WeIdAuthentication weIdAuthentication = new WeIdAuthentication();
        weIdAuthentication.setWeId(publisher);
        weIdAuthentication.setWeIdPrivateKey(new WeIdPrivateKey());
        weIdAuthentication.getWeIdPrivateKey().setPrivateKey(privateKey);

        CptMapArgs cptMapArgs = new CptMapArgs();
        cptMapArgs.setWeIdAuthentication(weIdAuthentication);
        cptMapArgs.setCptJsonSchema(claim); // 这是个 map哦

        // create CPT by SDK
        //
        // 注册 CPT 模板信息
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info(
            "registerCpt is result,errorCode:{},errorMessage:{}", 
            response.getErrorCode(),
            response.getErrorMessage()
        );
        return response;
    }

    /**
    * TODO 创建 一个 凭证详情
     * create credential.
     * 
     * @param cptId the cptId of CPT 
     * @param issuer the weId of issue
     * @param privateKey the private key of issuer
     * @param claimDate the data of claim
     * @return returns credential
     */
    @Override
    public ResponseData<CredentialWrapper> createCredential(
        Integer cptId, 
        String issuer,
        String privateKey,
        Map<String, Object> claimDate) {

        // build createCredential parameters.
        //
        // 构建 凭证入参
        CreateCredentialArgs registerCptArgs = new CreateCredentialArgs();
        registerCptArgs.setCptId(cptId);
        registerCptArgs.setIssuer(issuer);
        registerCptArgs.setWeIdPrivateKey(new WeIdPrivateKey());
        registerCptArgs.getWeIdPrivateKey().setPrivateKey(privateKey);
        registerCptArgs.setClaim(claimDate);

        // the validity period is 360 days
        registerCptArgs
            .setExpirationDate(System.currentTimeMillis() + EXPIRATION_DATE);

        // create credentials by SDK.
        //
        // 发起 创建凭证
        //
        // 主要是校验入参, 根据入参 构建出 credential 的各个字段, 其中主要有 选择性披露的字段 和  相关证明(签名)
        //  其中还声称了 对应 credential 的Id (由 UUID 生成)
        //
        // todo 可以知道这些动作其实现实中都是在 第三方机构 做的, 因为 电子凭证是 发行方颁发的哦
        ResponseData<CredentialWrapper> response = 
            credentialService.createCredential(registerCptArgs);
        logger.info(
            "createCredential is result,errorCode:{},errorMessage:{}",
            response.getErrorCode(), 
            response.getErrorMessage()
        );
        return response;
    }

    /**
    *
    * todo 用人单位校验 Credential 的正确性
    *
     * verifyEvidence credential.
     * 
     * @param credentialJson credentials in JSON format
     * @return returns the result of verifyEvidence
     */
    @Override
    public ResponseData<Boolean> verifyCredential(String credentialJson) {

        ResponseData<Boolean> verifyResponse = null;

        // 序列化成 class
        Credential credential = DataToolUtils.deserialize(credentialJson, Credential.class);

        // verifyEvidence credential on chain.
        //
        // todo chain 上校验 Credential 的正确性
        //
        //      校验 CPT 的 json-schame
        //      校验 Credential 的时效性
        //      校验 Signature 信息
        //      校验 ...
        verifyResponse = credentialService.verify(credential);
        logger.info(
            "verifyCredential is result,errorCode:{},errorMessage:{}",
            verifyResponse.getErrorCode(), 
            verifyResponse.getErrorMessage()
        );
        return verifyResponse;
    }
}
