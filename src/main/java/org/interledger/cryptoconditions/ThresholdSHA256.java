package org.interledger.cryptoconditions;

import java.util.EnumSet;
import java.util.List;

import org.interledger.cryptoconditions.types.FulfillmentPayload;
import org.interledger.cryptoconditions.types.MessagePayload;

public class ThresholdSHA256 extends FulfillmentBase {

   public class WeightedFulfillment {
       final int weight;
       final Fulfillment subff;
       public WeightedFulfillment(int weight, Fulfillment subfulfillment) {
           this.weight = weight;
           this.subff = subfulfillment;
       }
   }
   private final int threshold;
   private final List<WeightedFulfillment> subfulfillments;
   
   private ThresholdSHA256(ConditionType type, FulfillmentPayload payload, 
           int threshold, List<Integer>weight_l, List<Fulfillment> ff_l){
       if (weight_l.size() != ff_l.size()) {
           throw new RuntimeException("Can't zip weight_l && ff_l. Size differs ");
       }
       List<WeightedFulfillment> wff_l = new java.util.ArrayList<WeightedFulfillment>();
       for (int idx=0; idx< weight_l.size(); idx++) {
           wff_l.add(new WeightedFulfillment(weight_l.get(idx), ff_l.get(idx)));
       }
       this.threshold = threshold;
       this.subfulfillments = wff_l;
       throw new RuntimeException("FIXME Implement?");
   }
    @Override
    public Condition generateCondition() {
        throw new RuntimeException("not implemented"); // FIXME
    }

    @Override
    public boolean validate(MessagePayload message) {
        throw new RuntimeException("not implemented"); // FIXME
    }

    private EnumSet<FeatureSuite>  getBitmask () {
      EnumSet<FeatureSuite>  result = super.getFeatures();
      for (WeightedFulfillment ff : subfulfillments ){
          EnumSet<FeatureSuite> childFeatures = ff.subff.getFeatures();
          for (FeatureSuite fs : childFeatures) {
              if (! result.contains(fs)) { result.add(fs); }
          }
      }
      return result;
    }

}


//writeHashPayload (hasher) /* Produce the contents of the condition hash. */ {
//  const subconditions = this.subconditions // Serialize each subcondition with weight
//    .map((c) => { writer.writeVarUInt(c.weight),  writer.write(getConditionBinary()) })
//  const sortedSubconditions = this.constructor.sortBuffers(subconditions)
//  hasher.writeUInt32(this.threshold)
//  hasher.writeVarUInt(sortedSubconditions.length)
//  sortedSubconditions.forEach((c) => hasher.write(c))
//}
///** Calculate the worst case length of a set of conditions.
// * longest possible length for valid, minimal set of subconditions. */
//static calculateWorstCaseLength (threshold, weight_size_l, idx = 0) {
//    if (threshold <= 0) return 0
//    if (idx > weight_size_l.length) return -Infinity
//    ws = weight_size_l[index]; size = ws.size; weight = ws.weight; idx++;
//    return Math.max(
//      size+calculateWorstCaseLength(threshold-.weight,weight_size_l,idx)
//           calculateWorstCaseLength(threshold        ,weight_size_l,idx) )
//}
///* Calculates the longest possible fulfillment length.
// * In a threshold condition, the maximum length of the fulfillment depends on
// * the maximum lengths of the fulfillments of the subconditions. However,
// * usually not all subconditions must be fulfilled in order to meet the
// * threshold.
// * Consequently, this method relies on an algorithm to determine which
// * combination of fulfillments, where no fulfillment can be left out, results
// * in the largest total fulfillment size. */
//calculateMaxFulfillmentLength () { // Calculate length of longest fulfillments
//  let totalConditionLength = 0
//  const weight_size_l = this.subconditions
//    .map((cond) => {
//      const conditionLength = this.constructor.predictSubconditionLength(cond)
//      const fulfillmentLength = this.constructor.predictSubfulfillmentLength(cond)
//      totalConditionLength += conditionLength
//      return { weight: cond.weight,size: fulfillmentLength - conditionLength}
//    }).sort((a, b) => b.weight - a.weight)
//  const worstCaseFulfillmentsLength = totalConditionLength +
//    this.constructor.calculateWorstCaseLength( this.threshold, weight_size_l)
//  if (worstCaseFulfillmentsLength === -Infinity) 
//    throw new MissingDataError('Insufficient subconditions/weights to meet the threshold')
//  // Calculate resulting total maximum fulfillment size
//  const predictor = new Predictor()
//  predictor.writeUInt32(this.threshold)              // threshold
//  predictor.writeVarUInt(this.subconditions.length)  // count
//  this.subconditions.forEach((cond) => {
//    predictor.writeUInt8()                 // presence bitmask
//    if (cond.weight !== 1) predictor.writeUInt32(cond.weight)
//  })
//  // Represents the sum of CONDITION/FULFILLMENT values
//  predictor.skip(worstCaseFulfillmentsLength)
//  return predictor.getSize()
//}
//
//static predictSubconditionLength(cond){return cond.body.getConditionBinary().length}
//
//static predictSubfulfillmentLength (cond) {
//  const fulfillmentLength = getMaxFulfillmentLength()
//  predictor.writeUInt16()                                      // type
//  predictor.writeVarOctetString({ length: fulfillmentLength }) // payload
//  return predictor.getSize()
//}
//

//
////  selects smallest combination of fulfillments meeting a threshold.
//function calculateSmallestValidFulfillmentSet (threshold, fulfillments, state) {
//  state = state || { index: 0, size: 0, set: [] }
//  if (threshold <= 0) { return { size: state.size, set: state.set }
//  if (state.index > fulfillments.length) return { size: Infinity }
//  nextFF = fulfillments[state.index]
//  withNext = this.calculateSmallestValidFulfillmentSet(
//    threshold - nextFF.weight, fulfillments,
//    { size: state.size + nextFF.size,
//      index: state.index + 1,
//      set: state.set.concat(nextFF.index) } )
//  withoutNext = this.calculateSmallestValidFulfillmentSet(
//    threshold,                 fulfillments,
//    { size: state.size + nextFF.omitSize,
//      index: state.index + 1,
//      set: state.set } )
//  return withNext.size < withoutNext.size ? withNext : withoutNext
//}}
//
//writePayload (writer) { /* Generate the fulfillment OER payload. */
//  const subfulfillments = this.subconditions.map((x, i) => (
//      Object.assign({}, x, {
//        index: i,
//        size: x.body.serializeBinary().length,
//        omitSize: x.body.getConditionBinary().length
//      })
//    )
//
//  const smallestSet = this.constructor.calculateSmallestValidFulfillmentSet(
//    this.threshold, subfulfillments).set
//
//  const optimizedSubfulfillments =
//    // Take minimum set of fulfillments and turn rest into conditions
//    this.subconditions.map((c, i) => {
//      if (c.type !== FULFILLMENT || smallestSet.indexOf(i) !== -1) return c
//      return Object.assign({}, c, { type: CONDITION, body: c.body.getCondition() })
//    })
//
//  const serializedSubconditions = optimizedSubfulfillments
//    .map((cond) => {
//      const writer = new Writer()
//      writer.writeVarUInt(cond.weight)
//      writer.writeVarOctetString(cond.type === FULFILLMENT ? cond.body.serializeBinary() : EMPTY_BUFFER)
//      writer.writeVarOctetString(cond.type === CONDITION ? cond.body.serializeBinary() : EMPTY_BUFFER)
//      return writer.getBuffer()
//    })
//
//  const sortedSubconditions = this.constructor.sortBuffers(serializedSubconditions)
//
//  writer.writeVarUInt(this.threshold)
//  writer.writeVarUInt(sortedSubconditions.length)
//  sortedSubconditions.forEach(writer.write.bind(writer))
//}
//
//static sortBuffers (buffers) {
//  return buffers.slice().sort((a, b) => ( a.length !== b.length
//    ? a.length - b.length : Buffer.compare(a, b)))
//}
//
//validate (message) {
//  const fulfillments = this.subconditions.filter((cond) => cond.type === FULFILLMENT)
//
//  let minWeight = Infinity // Find total weight and smallest individual weight
//  const totalWeight = fulfillments.reduce((total, cond) => {
//    minWeight = Math.min(minWeight, cond.weight)
//    return total + cond.weight
//  }, 0)
//
//  if (totalWeight < this.threshold) throw Error('Threshold not met')
//
//  // the set must be minimal, there mustn't be any fulfillments we could take out
//  if (this.threshold + minWeight <= totalWeight) 
//    throw new Error('Fulfillment is not minimal')
//
//  return fulfillments.every((f) => f.body.validate(message))
//}
