// Copyright 2021 iLogtail Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package sql

import (
	"github.com/alibaba/ilogtail/pkg/logger"
	"github.com/alibaba/ilogtail/pkg/models"
	"github.com/alibaba/ilogtail/pkg/pipeline"
	"github.com/xwb1989/sqlparser"
)

type ProcessorSql struct {
	Script     string
	NoKeyError bool
	Plan       SelectPlan
	context    pipeline.Context
}

const pluginName = "processor_sql"

func (p *ProcessorSql) Init(context pipeline.Context) error {
	p.context = context
	//1. parse sql scipt
	astNode, err := sqlparser.Parse(p.Script)
	// gop.P(astNode)
	if err != nil {
		logger.Errorf(p.context.GetRuntimeContext(), "sql parse error: %v", err.Error())
		return err
	}
	//check sql type
	var selectStmt *sqlparser.Select
	var ok bool
	if selectStmt, ok = astNode.(*sqlparser.Select); !ok {
		logger.Errorf(p.context.GetRuntimeContext(), "sql parse error: %v", "only support select statement!")
		return err
	}
	//2. generate select plan
	p.Plan = SelectPlan{}
	err = p.genProjectOper(selectStmt)
	if err != nil {
		logger.Errorf(p.context.GetRuntimeContext(), "error in parse column: %v", err.Error())
		return err
	}
	err = p.genPredicateOper(selectStmt)
	if err != nil {
		logger.Errorf(p.context.GetRuntimeContext(), "error in parse condition: %v", err.Error())
		return err
	}
	// gop.P(p.Plan)
	return nil
}

func (p *ProcessorSql) Process(in *models.PipelineGroupEvents, context pipeline.PipelineContext) {
	//process select plan
	for _, event := range in.Events {
		if event.GetType() == models.EventTypeLogging {
			logEvent := event.(*models.Log)
			p.processEvent(logEvent)
		} else {
			logger.Errorf(p.context.GetRuntimeContext(), "con not support non-loggingEvent type:", event.GetName())
		}
	}
	context.Collector().Collect(in.Group, in.Events...)
}

func (p *ProcessorSql) processEvent(log *models.Log) {
	origin := log.GetIndices()

	var in LogContentType = models.NewKeyValues[string]()
	for k, v := range origin.Iterator() {
		if v, ok := v.(string); !ok {
			logger.Errorf(p.context.GetRuntimeContext(), "error in processEvent: %v", "not stringLogContents")
			return
		} else {
			in.Add(k, v)
		}
	}
	success, err := p.predicate(&in)
	if err != nil {
		logger.Errorf(p.context.GetRuntimeContext(), "error in predicate: %v", err.Error())
		log.SetIndices(nil)
		return
	}
	if !success {
		log.SetIndices(nil)
		return
	}
	out, err := p.project(&in)
	if err != nil {
		logger.Errorf(p.context.GetRuntimeContext(), "error in project: %v", err.Error())
		return
	}
	// gop.P(out)
	log.SetIndices(*out)
}

func (*ProcessorSql) Description() string {
	return "sql processor for logtail"
}

func init() {
	pipeline.Processors[pluginName] = func() pipeline.Processor {
		return &ProcessorSql{
			Script:     "",
			NoKeyError: true,
		}
	}
}
