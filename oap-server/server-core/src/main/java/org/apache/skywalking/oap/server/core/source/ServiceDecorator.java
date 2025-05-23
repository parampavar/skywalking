/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.apache.skywalking.oap.server.core.source;

import org.apache.skywalking.oap.server.core.analysis.ISourceDecorator;

public class ServiceDecorator implements ISourceDecorator<Service> {
    @Override
    public int getSourceScope() {
        return DefaultScopeDefine.SERVICE;
    }

    /**
     * Set the Layer name to attr0
     * @param source The source instance to be decorated
     */
    @Override
    public void decorate(final Service source) {
        source.setAttr0(source.getLayer().name());
    }
}
