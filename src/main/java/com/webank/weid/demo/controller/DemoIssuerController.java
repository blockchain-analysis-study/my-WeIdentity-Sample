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

package com.webank.weid.demo.controller;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.webank.weid.constant.ErrorCode;
import com.webank.weid.demo.common.model.CptModel;
import com.webank.weid.demo.common.model.CreateCredentialModel;
import com.webank.weid.demo.common.util.PrivateKeyUtil;
import com.webank.weid.demo.service.DemoService;
import com.webank.weid.protocol.base.CptBaseInfo;
import com.webank.weid.protocol.base.CredentialWrapper;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.util.DataToolUtils;

/**
 * Demo Controller.
 *
 * @author darwindu
 */
@RestController
@Api(description = "Issuer: Credential的发行者。"
        + "会验证实体对WeIdentity DID的所有权，其次发行实体相关的Credential。",
    tags = {"Issuer相关接口"})
public class DemoIssuerController {

    private static final Logger logger = LoggerFactory.getLogger(DemoIssuerController.class);

    @Autowired
    private DemoService demoService;

    /**
    *  发行方 自己创建 WeId接口
     * create weId without parameters and call the settings property method.
     *
     * @return returns weId and public key
     */
    @ApiOperation(value = "创建WeId")
    @PostMapping("/step1/issuer/createWeId")
    public ResponseData<CreateWeIdDataResult> createWeId() {
        return demoService.createWeId();
    }

    /**
    *  发行方在链上 注册 CPT 模板
     * institutional publication of CPT.
     * claim is a JSON object
     * @return returns CptBaseInfo
     */
    @ApiOperation(value = "注册CPT")
    @PostMapping("/step2/registCpt")
    public ResponseData<CptBaseInfo> registCpt(
        @ApiParam(name = "cptModel", value = "CPT模板")
        @RequestBody CptModel cptModel) {

        ResponseData<CptBaseInfo> response;
        try {
            if (null == cptModel) {
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }

            // 获取外部入参的 CPT 发布者 todo (发布者的 WeId, did:weid:1:0x19607cf2bc4538b49847b43688acf3befc487a41)
            String publisher = cptModel.getPublisher();
            // 获取外部入参的 CPT 的Claim信息 todo (一个 json字符串, 详细 看 cptModel 中的定义)
            String claim = DataToolUtils.mapToCompactJson(cptModel.getClaim());

            // get the private key from the file according to weId.
            String privateKey
                = PrivateKeyUtil.getPrivateKeyByWeId(PrivateKeyUtil.KEY_DIR, publisher);
            logger.info("param,publisher:{},privateKey:{},claim:{}", publisher, privateKey, claim);

            // converting claim in JSON format to map.
            Map<String, Object> claimMap = new HashMap<String, Object>();

            // 将 Claim 的json信息转换成 map
            claimMap = 
                (Map<String, Object>) DataToolUtils.deserialize(
                    claim,
                    claimMap.getClass()
                );

            // call method to register CPT on the chain.
            //
            // 将 claimMap 和 pusher 做签名，并将 claimMap 和 signature 一起存储链上
            response = demoService.registCpt(publisher, privateKey, claimMap);
            logger.info("registCpt response: {}", DataToolUtils.objToJsonStrWithNoPretty(response));
            return response;
        } catch (Exception e) {
            logger.error("registCpt error", e);
            return new ResponseData<>(null, ErrorCode.TRANSACTION_EXECUTE_ERROR);
        }
    }

    /**
    *  TODO 现在 我这就是 发行方, 给某些人颁发 电子凭证哦
     * institutional publication of Credential.
     *
     * @return returns  credential
     * @throws IOException  it's possible to throw an exception
     */
    @ApiOperation(value = "创建电子凭证")
    @PostMapping("/step3/createCredential")
    public ResponseData<CredentialWrapper> createCredential(
        @ApiParam(name = "createCredentialModel", value = "创建电子凭证模板")
        @RequestBody CreateCredentialModel createCredentialModel) {

        ResponseData<CredentialWrapper> response;
        try {

            if (null == createCredentialModel) {
                return new ResponseData<>(null, ErrorCode.ILLEGAL_INPUT);
            }
            // getting cptId data.
            //
            // 获取外部入参的 cptId
            Integer cptId = createCredentialModel.getCptId();
            // getting issuer data.
            //
            // 获取外部入参的 发行者 weId (和 cptId 匹配)
            String issuer = createCredentialModel.getIssuer();
            // getting claimData data.
            //
            // 获取外部入参的 Claim 详情
            String claimData = DataToolUtils.mapToCompactJson(createCredentialModel.getClaimData());

            // get the private key from the file according to weId.
            //
            // 根据
            String privateKey = PrivateKeyUtil.getPrivateKeyByWeId(PrivateKeyUtil.KEY_DIR, issuer);
            logger.info(
                "param,cptId:{},issuer:{},privateKey:{},claimData:{}", 
                cptId, 
                issuer,
                privateKey, 
                claimData
            );

            // converting claimData in JSON format to map.
            Map<String, Object> claimDataMap = new HashMap<String, Object>();
            claimDataMap = 
                (Map<String, Object>) DataToolUtils.deserialize(
                    claimData,
                    claimDataMap.getClass()
                );

            // call method to create credentials.
            //
            // todo 创建 电子凭证 详情
            response = demoService.createCredential(cptId, issuer, privateKey, claimDataMap);
            logger.info("createCredential response: {}",
                DataToolUtils.objToJsonStrWithNoPretty(response));
            return response;
        } catch (Exception e) {
            logger.error("createCredential error", e);
            return new ResponseData<CredentialWrapper>(null, ErrorCode.CREDENTIAL_ERROR);
        }
    }


}
