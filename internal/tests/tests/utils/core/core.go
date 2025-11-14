package core

import (
	"context"
	"fmt"

	"github.com/ellanetworks/core/client"
)

type SubscriberConfig struct {
	Imsi           string
	Key            string
	SequenceNumber string
	OPc            string
	PolicyName     string
}

type PolicyConfig struct {
	Name            string
	BitrateUplink   string
	BitrateDownlink string
	Var5qi          int32
	Arp             int32
	DataNetworkName string
}

type DataNetworkConfig struct {
	Name   string
	IPPool string
	DNS    string
	Mtu    int32
}

type OperatorID struct {
	MCC string
	MNC string
}

type OperatorSlice struct {
	SST int32
	SD  string
}

type OperatorTracking struct {
	SupportedTACs []string
}

type OperatorConfig struct {
	ID       OperatorID
	Slice    OperatorSlice
	Tracking OperatorTracking
}

type EllaCoreConfig struct {
	Operator     OperatorConfig
	DataNetworks []DataNetworkConfig
	Policies     []PolicyConfig
	Subscribers  []SubscriberConfig
}

type EllaCoreEnv struct {
	Client *client.Client
	Config EllaCoreConfig
}

func NewEllaCoreEnv(client *client.Client, config EllaCoreConfig) *EllaCoreEnv {
	return &EllaCoreEnv{
		Client: client,
		Config: config,
	}
}

func (c *EllaCoreEnv) Create(ctx context.Context) error {
	err := c.Delete(ctx)
	if err != nil {
		return fmt.Errorf("could not clean up existing EllaCore environment: %v", err)
	}

	err = c.updateOperator(ctx)
	if err != nil {
		return fmt.Errorf("could not update operator: %v", err)
	}

	err = c.createDataNetworks(ctx)
	if err != nil {
		return fmt.Errorf("could not create data networks: %v", err)
	}

	err = c.createPolicies(ctx)
	if err != nil {
		return fmt.Errorf("could not create policies: %v", err)
	}

	err = c.createSubs(ctx)
	if err != nil {
		return fmt.Errorf("could not create subscribers: %v", err)
	}

	return nil
}

// Delete all subscribers, policies, and data networks created during the test.
func (c *EllaCoreEnv) Delete(ctx context.Context) error {
	err := c.deleteSubscribers(ctx)
	if err != nil {
		return fmt.Errorf("could not delete subscribers: %v", err)
	}

	err = c.deletePolicies(ctx)
	if err != nil {
		return fmt.Errorf("could not delete policies: %v", err)
	}

	err = c.deleteDataNetworks(ctx)
	if err != nil {
		return fmt.Errorf("could not delete data networks: %v", err)
	}

	return nil
}

func (c *EllaCoreEnv) updateOperator(ctx context.Context) error {
	opConfig, err := c.Client.GetOperator(ctx)
	if err != nil {
		return fmt.Errorf("failed to get operator: %v", err)
	}

	if opConfig.ID.Mcc != c.Config.Operator.ID.MCC || opConfig.ID.Mnc != c.Config.Operator.ID.MNC {
		err := c.Client.UpdateOperatorID(ctx, &client.UpdateOperatorIDOptions{
			Mcc: c.Config.Operator.ID.MCC,
			Mnc: c.Config.Operator.ID.MNC,
		})
		if err != nil {
			return fmt.Errorf("failed to update operator ID: %v", err)
		}
	}

	if opConfig.Slice.Sst != int(c.Config.Operator.Slice.SST) || opConfig.Slice.Sd != c.Config.Operator.Slice.SD {
		err := c.Client.UpdateOperatorSlice(ctx, &client.UpdateOperatorSliceOptions{
			Sst: int(c.Config.Operator.Slice.SST),
			Sd:  c.Config.Operator.Slice.SD,
		})
		if err != nil {
			return fmt.Errorf("failed to update operator slice: %v", err)
		}
	}

	currentTACsMap := make(map[string]bool)
	for _, tac := range opConfig.Tracking.SupportedTacs {
		currentTACsMap[tac] = true
	}

	needUpdate := false

	for _, tac := range c.Config.Operator.Tracking.SupportedTACs {
		if !currentTACsMap[tac] {
			needUpdate = true
			break
		}
	}

	if needUpdate {
		err := c.Client.UpdateOperatorTracking(ctx, &client.UpdateOperatorTrackingOptions{
			SupportedTacs: c.Config.Operator.Tracking.SupportedTACs,
		})
		if err != nil {
			return fmt.Errorf("failed to update operator tracking: %v", err)
		}
	}

	return nil
}

func (c *EllaCoreEnv) createDataNetworks(ctx context.Context) error {
	for _, dnn := range c.Config.DataNetworks {
		existingDNN, _ := c.Client.GetDataNetwork(ctx, &client.GetDataNetworkOptions{
			Name: dnn.Name,
		})

		if existingDNN == nil {
			err := c.Client.CreateDataNetwork(ctx, &client.CreateDataNetworkOptions{
				Name:   dnn.Name,
				IPPool: dnn.IPPool,
				DNS:    dnn.DNS,
				Mtu:    dnn.Mtu,
			})
			if err != nil {
				return fmt.Errorf("failed to create data network: %v", err)
			}
		}
	}

	return nil
}

func (c *EllaCoreEnv) createPolicies(ctx context.Context) error {
	for _, policy := range c.Config.Policies {
		existingPolicy, _ := c.Client.GetPolicy(ctx, &client.GetPolicyOptions{
			Name: policy.Name,
		})

		if existingPolicy == nil {
			err := c.Client.CreatePolicy(ctx, &client.CreatePolicyOptions{
				Name:            policy.Name,
				BitrateUplink:   policy.BitrateUplink,
				BitrateDownlink: policy.BitrateDownlink,
				Var5qi:          policy.Var5qi,
				Arp:             policy.Arp,
				DataNetworkName: policy.DataNetworkName,
			})
			if err != nil {
				return fmt.Errorf("failed to create policy: %v", err)
			}
		}
	}

	return nil
}

func (c *EllaCoreEnv) createSubs(ctx context.Context) error {
	for _, sub := range c.Config.Subscribers {
		existingSub, _ := c.Client.GetSubscriber(ctx, &client.GetSubscriberOptions{
			ID: sub.Imsi,
		})

		if existingSub == nil {
			err := c.Client.CreateSubscriber(ctx, &client.CreateSubscriberOptions{
				Imsi:           sub.Imsi,
				Key:            sub.Key,
				SequenceNumber: sub.SequenceNumber,
				PolicyName:     sub.PolicyName,
				OPc:            sub.OPc,
			})
			if err != nil {
				return fmt.Errorf("failed to create subscriber: %v", err)
			}
		}
	}

	return nil
}

func (c *EllaCoreEnv) deleteSubscribers(ctx context.Context) error {
	subs, err := c.Client.ListSubscribers(ctx, &client.ListParams{
		Page:    1,
		PerPage: 100,
	})
	if err != nil {
		return fmt.Errorf("failed to list subscribers: %v", err)
	}

	for _, sub := range subs.Items {
		err := c.Client.DeleteSubscriber(ctx, &client.DeleteSubscriberOptions{
			ID: sub.Imsi,
		})
		if err != nil {
			return fmt.Errorf("failed to delete subscriber %s: %v", sub.Imsi, err)
		}
	}

	return nil
}

func (c *EllaCoreEnv) deletePolicies(ctx context.Context) error {
	pols, err := c.Client.ListPolicies(ctx, &client.ListParams{
		Page:    1,
		PerPage: 100,
	})
	if err != nil {
		return fmt.Errorf("failed to list policies: %v", err)
	}

	for _, policy := range pols.Items {
		err := c.Client.DeletePolicy(ctx, &client.DeletePolicyOptions{
			Name: policy.Name,
		})
		if err != nil {
			return fmt.Errorf("failed to delete policy %s: %v", policy.Name, err)
		}
	}

	return nil
}

func (c *EllaCoreEnv) deleteDataNetworks(ctx context.Context) error {
	dnns, err := c.Client.ListDataNetworks(ctx, &client.ListParams{
		Page:    1,
		PerPage: 100,
	})
	if err != nil {
		return fmt.Errorf("failed to list data networks: %v", err)
	}

	for _, dnn := range dnns.Items {
		err := c.Client.DeleteDataNetwork(ctx, &client.DeleteDataNetworkOptions{
			Name: dnn.Name,
		})
		if err != nil {
			return fmt.Errorf("failed to delete data network %s: %v", dnn.Name, err)
		}
	}

	return nil
}
